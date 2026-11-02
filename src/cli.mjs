#!/usr/bin/env node
/**
 * supabase-exposure-check
 * What can an anonymous visitor reach in your Supabase app?
 *
 *   npx github:Joyhacks/supabase-exposure-check https://your-app.lovable.app
 *
 * Read-only. Uses only the public key your site already ships. Never reads
 * row contents, never writes, never uses a leaked privileged key.
 * Only scan apps you own or have permission to test.
 */
import { crawl } from './site.mjs';
import { empty, mask } from './bundle.mjs';
import { checkAuth, listSchema, checkTable, listBuckets, checkBucket } from './checks.mjs';

const SENSITIVE = /(user|profile|account|customer|client|member|order|payment|invoice|subscription|billing|message|chat|conversation|email|contact|lead|booking|appointment|application|patient|document|address|transaction|wallet|token|secret|session|admin|employee|salary)/i;
const MAX_TABLES = 150;
const LEVELS = ['critical', 'high', 'medium', 'info', 'ok'];

function parseArgs(argv) {
  const a = { site: null, url: null, key: null, tables: [], buckets: [], count: false, json: false, timeout: 15 };
  const list = (s) => s.split(',').map((x) => x.trim()).filter(Boolean);
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    const next = () => {
      if (i + 1 >= argv.length) throw new Error(`${k} needs a value`);
      return argv[++i];
    };
    if (k === '--supabase-url') a.url = next();
    else if (k === '--key') a.key = next();
    else if (k === '--tables') a.tables = list(next());
    else if (k === '--buckets') a.buckets = list(next());
    else if (k === '--count') a.count = true;
    else if (k === '--json') a.json = true;
    else if (k === '--timeout') a.timeout = Number(next());
    else if (k === '--help' || k === '-h') a.help = true;
    else if (k.startsWith('--')) throw new Error(`Unknown option ${k}`);
    else if (!a.site) a.site = k;
    else throw new Error(`Unexpected argument ${k}`);
  }
  if (!a.help && !a.site && !a.url) throw new Error('Give a site URL, or --supabase-url with --key');
  if (a.site && !/^https?:\/\//.test(a.site)) a.site = 'https://' + a.site;
  if (!(a.timeout > 0)) throw new Error('--timeout must be a positive number of seconds');
  return a;
}

async function pool(items, size, fn) {
  const out = [];
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(size, items.length) }, async () => {
    while (i < items.length) {
      const idx = i++;
      out[idx] = await fn(items[idx]);
    }
  }));
  return out;
}

export async function run(argv, { fetchFn = globalThis.fetch, log = console.log } = {}) {
  let a;
  try {
    a = parseArgs(argv);
  } catch (e) {
    log(`supabase-exposure-check: ${e.message}\nRun with --help for usage.`);
    return { code: 2 };
  }
  if (a.help) {
    log(`Usage:
  supabase-exposure-check <site-url> [options]
  supabase-exposure-check --supabase-url https://REF.supabase.co --key <anon key> [options]

Options:
  --tables a,b      Also check these tables
  --buckets a,b     Also check these storage buckets
  --count           Ask for exact row counts on readable tables (heavier on big tables)
  --json            Machine-readable output
  --timeout N       Seconds per request (default 15)

Read-only. Only scan apps you own or have permission to test.`);
    return { code: 0 };
  }

  const ms = a.timeout * 1000;
  const findings = [];
  const add = (level, title, detail = '', fix = '') => findings.push({ level, title, detail, fix });
  const progress = a.json ? () => {} : (s) => log(`  ${s}`);

  // 1. Read the site.
  let found = empty();
  if (a.site) {
    progress(`Reading ${a.site} ...`);
    try {
      const r = await crawl(fetchFn, a.site, { timeoutMs: ms, log: progress });
      found = r.found;
      if (r.errors.length) progress(`${r.errors.length} script(s) could not be fetched.`);
    } catch (e) {
      add('info', 'Could not read the site', e.message, 'Check the URL, or pass --supabase-url and --key directly.');
    }
  }

  // 2. Secrets in the shipped JavaScript.
  for (const k of found.keys.values()) {
    if (k.role === 'service_role') {
      add('critical', 'Supabase service_role key is in your public JavaScript', `Key ${mask(k.token)}${k.ref ? ` for project ${k.ref}` : ''}. This key bypasses every RLS policy. Anyone who opens DevTools can read, change or delete all of your data.`,
        'Rotate it now: Supabase dashboard > Project Settings > API. Then move the code that needed it into an Edge Function or server route. This tool will not use the key.');
    }
  }
  for (const s of found.secrets.values()) {
    const level = s.id === 'stripe-test-secret' ? 'high' : 'critical';
    add(level, `${s.what} is in your public JavaScript`, `Value ${mask(s.value)}.`, 'Rotate it with the provider, then make the call that needs it from a server function instead of the browser.');
  }

  // 3. Which project and which public key.
  const ref = a.url ? (a.url.match(/https:\/\/([a-z0-9]{20})\.supabase/) || [])[1] || null : [...found.projects][0] || null;
  const base = a.url ? a.url.replace(/\/+$/, '') : ref ? `https://${ref}.supabase.co` : null;
  if (found.projects.size > 1 && !a.url) add('info', 'More than one Supabase project referenced', [...found.projects].join(', '), `Checked ${ref}. Use --supabase-url to check another.`);

  let key = a.key;
  if (key) {
    let p = null;
    try {
      p = key.startsWith('eyJ') ? JSON.parse(Buffer.from(key.split('.')[1] || '', 'base64url').toString()) : null;
    } catch { /* not a JWT we can read; treat as opaque */ }
    if ((p && p.role === 'service_role') || key.startsWith('sb_secret_')) {
      log('Refusing to run with a privileged key. Pass the anon or publishable key, which is what a visitor sees.');
      return { code: 2 };
    }
  } else {
    const anon = [...found.keys.values()].filter((k) => k.role === 'anon');
    key = (anon.find((k) => k.ref === ref) || anon[0] || {}).token || null;
  }

  if (!base) add('info', 'No Supabase project found', 'The site does not reference a *.supabase.co URL in its HTML or JavaScript.', 'If it uses a custom domain, pass --supabase-url and --key.');
  else if (!key) add('info', 'Found the project but not its public key', `Project ${base}.`, 'Pass the anon or publishable key with --key.');

  const report = { site: a.site, project: base, key: key ? mask(key) : null, tables: [], buckets: [], rpcs: [], findings };

  if (base && key) {
    progress(`Checking ${base} with the public key ...`);

    // 4. Auth settings.
    const auth = await checkAuth(fetchFn, base, key, ms);
    report.auth = auth;
    if (auth.ok && auth.signupOpen && auth.autoconfirm) {
      add('high', 'Anyone can create a confirmed account instantly', 'Email signup is open and email confirmation is off. Any RLS policy that only checks "authenticated" is effectively public.',
        'Turn on email confirmation (Authentication > Providers > Email), and write policies that check ownership, for example auth.uid() = user_id.');
    } else if (auth.ok && auth.signupOpen) {
      add('info', 'Public signup is open', `Email confirmation is on.${auth.providers.length ? ` Social providers: ${auth.providers.join(', ')}.` : ''}`, 'Fine for most apps. Make sure policies check ownership, not just "authenticated".');
    }

    // 5. Tables and functions.
    const schema = await listSchema(fetchFn, base, key, ms);
    if (schema.exposed) add('info', 'Table and function names are listable by anyone', `${schema.tables.length} table(s)/view(s) and ${schema.rpcs.length} function(s) appear in the public API schema.`, 'No data is exposed by this alone, but it maps your database for an attacker. Newer Supabase API keys restrict it.');
    const tables = [...new Set([...a.tables, ...found.tables, ...schema.tables])].slice(0, MAX_TABLES);
    const rpcs = [...new Set([...found.rpcs, ...schema.rpcs])];
    report.rpcs = rpcs;

    const results = await pool(tables, 4, (t) => checkTable(fetchFn, base, key, t, ms, { count: a.count }));
    report.tables = results;
    for (const r of results.filter((x) => x.state === 'readable')) {
      const sensitive = SENSITIVE.test(r.table);
      add(sensitive ? 'critical' : 'high', `Anyone can read table "${r.table}"`,
        `${r.rows != null ? `${r.rows} row(s)` : 'At least one row'} visible with only the public key.${sensitive ? ' The name suggests personal or business data.' : ' If this is meant to be public (products, blog posts), this is fine.'}`,
        `Enable RLS and add a policy that scopes reads, for example:\n  alter table public.${r.table} enable row level security;\n  create policy "own rows" on public.${r.table} for select using (auth.uid() = user_id);`);
    }
    if (tables.length > MAX_TABLES) add('info', `Checked the first ${MAX_TABLES} tables`, '', 'Use --tables to target specific ones.');
    if (rpcs.length) add('info', `${rpcs.length} database function(s) callable from the browser`, rpcs.slice(0, 20).join(', ') + (rpcs.length > 20 ? ', ...' : ''),
      'Anyone with the public key can call these. Each one that is SECURITY DEFINER must check auth.uid() itself and set search_path.');

    // 6. Storage.
    const bl = await listBuckets(fetchFn, base, key, ms);
    const buckets = [...new Set([...a.buckets, ...found.buckets, ...bl.buckets.map((b) => b.name)])];
    if (bl.visible) add('info', 'Bucket list is visible to anyone', bl.buckets.map((b) => `${b.name}${b.public ? ' (public)' : ''}`).join(', '));
    const bres = await pool(buckets, 4, (b) => checkBucket(fetchFn, base, key, b, ms));
    report.buckets = bres;
    for (const r of bres.filter((x) => x.state === 'listable')) {
      add('medium', `Anyone can list files in bucket "${r.bucket}"`, 'A stranger can enumerate every file name, and download files if the bucket is public.',
        'Restrict the select policy on storage.objects for this bucket, for example to (storage.foldername(name))[1] = auth.uid()::text.');
    }

    const ok = results.filter((r) => r.state === 'denied' || r.state === 'no_rows').length;
    if (tables.length) add('ok', `${ok} of ${tables.length} table(s) return nothing to an anonymous visitor`, results.filter((r) => ['denied', 'no_rows'].includes(r.state)).map((r) => r.table).join(', '));
    const unclear = results.filter((r) => ['error', 'unknown'].includes(r.state));
    if (unclear.length) add('info', `${unclear.length} table check(s) were inconclusive`, unclear.map((r) => `${r.table} (${r.detail})`).join(', '));
  }

  findings.sort((x, y) => LEVELS.indexOf(x.level) - LEVELS.indexOf(y.level));
  const counts = Object.fromEntries(LEVELS.map((l) => [l, findings.filter((f) => f.level === l).length]));
  report.summary = counts;
  const code = counts.critical || counts.high ? 1 : 0;

  if (a.json) {
    log(JSON.stringify(report, null, 2));
  } else {
    log('');
    for (const f of findings) {
      log(`[${f.level.toUpperCase()}] ${f.title}`);
      if (f.detail) log(`   ${f.detail.replace(/\n/g, '\n   ')}`);
      if (f.fix) log(`   Fix: ${f.fix.replace(/\n/g, '\n   ')}`);
      log('');
    }
    log(`Summary: ${LEVELS.map((l) => `${counts[l]} ${l}`).join(', ')}`);
    if (!findings.length) log('Nothing to report.');
    log('This checks what an anonymous visitor can reach. It does not replace a full security review.');
  }
  return { code, report };
}

const invoked = process.argv[1] && /(cli\.mjs|supabase-exposure-check)$/.test(process.argv[1]);
if (invoked) {
  run(process.argv.slice(2)).then(({ code }) => { process.exitCode = code; });
}
