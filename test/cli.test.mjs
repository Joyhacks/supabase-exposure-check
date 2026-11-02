import { test } from 'node:test';
import assert from 'node:assert/strict';
import { run } from '../src/cli.mjs';
import { extract } from '../src/bundle.mjs';
import { scriptUrls, chunkUrls } from '../src/site.mjs';

const REF = 'abcdefghijklmnopqrst';
const BASE = `https://${REF}.supabase.co`;
// Keys are built at runtime so this file holds nothing a secret scanner should flag.
const jwt = (payload) => ['eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9', Buffer.from(JSON.stringify(payload)).toString('base64url'), 'c2lnbmF0dXJlLXZhbHVlLWhlcmU'].join('.');
const ANON = jwt({ iss: 'supabase', ref: REF, role: 'anon' });
const SERVICE = jwt({ iss: 'supabase', ref: REF, role: 'service_role' });
const STRIPE = 'sk_live_' + 'Ab3dEf6hIj9kLm2nOp5qRs8t';

/** Tiny fake internet. routes: { 'GET https://x/y': () => Response } */
function fakeFetch(routes) {
  const calls = [];
  const fn = async (url, init = {}) => {
    const method = (init.method || 'GET').toUpperCase();
    calls.push({ method, url, headers: init.headers || {} });
    const path = url.split('?')[0];
    const handler = routes[`${method} ${url}`] || routes[`${method} ${path}`];
    if (!handler) return new Response('not found', { status: 404 });
    return handler(init);
  };
  fn.calls = calls;
  return fn;
}
const json = (body, status = 200) => () => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
const head = (range, status = 200) => () => new Response(null, { status, headers: range ? { 'content-range': range } : {} });
const text = (body) => () => new Response(body, { status: 200 });

const HTML = `<!doctype html><html><head>
<script type="module" crossorigin src="/assets/index-abc.js"></script>
<link rel="modulepreload" crossorigin href="/assets/vendor-123.js">
</head><body><div id="root"></div></body></html>`;

function leakyApp(extra = {}) {
  return fakeFetch({
    'GET https://app.test': text(HTML),
    'GET https://app.test/assets/index-abc.js': text(`const s=createClient("${BASE}","${ANON}");s.from("profiles").select("*");s.from("posts").select();s.storage.from("avatars").upload(f);s.rpc("get_stats");Array.from("xyz");const r=()=>import("/assets/Admin-def.js");`),
    'GET https://app.test/assets/vendor-123.js': text('/* react */'),
    'GET https://app.test/assets/Admin-def.js': text(`const a=createClient("${BASE}","${SERVICE}");const k="${STRIPE}";a.from("orders").delete();`),
    [`GET ${BASE}/auth/v1/settings`]: json({ disable_signup: false, mailer_autoconfirm: true, external: { google: true, github: false } }),
    [`GET ${BASE}/rest/v1/`]: json({ message: 'no' }, 401),
    [`HEAD ${BASE}/rest/v1/profiles`]: head('0-0/*'),
    [`HEAD ${BASE}/rest/v1/posts`]: head('0-0/*'),
    [`HEAD ${BASE}/rest/v1/orders`]: head('*/*'),
    [`GET ${BASE}/storage/v1/bucket`]: json([]),
    [`POST ${BASE}/storage/v1/object/list/avatars`]: json([{ name: 'a.png' }]),
    ...extra,
  });
}

const quiet = () => {
  const lines = [];
  const log = (l) => lines.push(String(l));
  log.text = () => lines.join('\n');
  return log;
};

test('leaky app: finds every problem and exits 1', async () => {
  const log = quiet();
  const { code, report } = await run(['https://app.test'], { fetchFn: leakyApp(), log });
  assert.equal(code, 1);
  const titles = report.findings.map((f) => `${f.level}: ${f.title}`);
  assert.ok(titles.includes('critical: Supabase service_role key is in your public JavaScript'));
  assert.ok(titles.includes('critical: Stripe live secret key is in your public JavaScript'));
  assert.ok(titles.includes('critical: Anyone can read table "profiles"'));
  assert.ok(titles.includes('high: Anyone can read table "posts"'));
  assert.ok(titles.includes('high: Anyone can create a confirmed account instantly'));
  assert.ok(titles.includes('medium: Anyone can list files in bucket "avatars"'));
  assert.ok(titles.some((t) => t.startsWith('info: 1 database function')));
  assert.equal(report.tables.find((t) => t.table === 'orders').state, 'no_rows');
  assert.ok(!report.tables.some((t) => t.table === 'xyz'), 'Array.from is not a table');
  assert.equal(report.findings[0].level, 'critical', 'sorted by severity');
});

test('never sends the leaked service_role key, never prints a full key', async () => {
  const f = leakyApp();
  const log = quiet();
  await run(['https://app.test'], { fetchFn: f, log });
  const supa = f.calls.filter((c) => c.url.startsWith(BASE));
  assert.ok(supa.length > 0);
  for (const c of supa) {
    assert.equal(c.headers.apikey, ANON, `${c.method} ${c.url}`);
    assert.ok(!JSON.stringify(c.headers).includes(SERVICE));
  }
  for (const secret of [ANON, SERVICE, STRIPE]) assert.ok(!log.text().includes(secret), 'full key printed');
});

test('only HEAD and file-list requests touch the database: no row data, no writes', async () => {
  const f = leakyApp();
  await run(['https://app.test'], { fetchFn: f, log: quiet() });
  for (const c of f.calls.filter((x) => x.url.includes('/rest/v1/') && x.url !== `${BASE}/rest/v1/`)) {
    assert.equal(c.method, 'HEAD');
    assert.match(c.url, /limit=1/);
  }
  const posts = f.calls.filter((c) => c.method === 'POST');
  assert.ok(posts.every((c) => c.url.includes('/storage/v1/object/list/')));
  assert.ok(!f.calls.some((c) => ['PUT', 'PATCH', 'DELETE'].includes(c.method)));
});

test('clean app exits 0', async () => {
  const f = fakeFetch({
    'GET https://clean.test': text('<script src="/assets/app.js"></script>'),
    'GET https://clean.test/assets/app.js': text(`createClient("${BASE}","${ANON}");x.from("profiles");x.from("notes")`),
    [`GET ${BASE}/auth/v1/settings`]: json({ disable_signup: false, mailer_autoconfirm: false, external: {} }),
    [`HEAD ${BASE}/rest/v1/profiles`]: head('*/*'),
    [`HEAD ${BASE}/rest/v1/notes`]: head(null, 401),
    [`GET ${BASE}/storage/v1/bucket`]: json([]),
  });
  const { code, report } = await run(['clean.test'], { fetchFn: f, log: quiet() });
  assert.equal(code, 0);
  assert.equal(report.summary.critical + report.summary.high, 0);
  assert.ok(report.findings.some((x) => x.level === 'ok' && x.title.startsWith('2 of 2 table')));
});

test('refuses to run with a privileged key', async () => {
  const log = quiet();
  assert.equal((await run(['--supabase-url', BASE, '--key', SERVICE], { fetchFn: fakeFetch({}), log })).code, 2);
  assert.match(log.text(), /Refusing/);
  assert.equal((await run(['--supabase-url', BASE, '--key', ['sb', 'secret', 'abcdefghijklmnopqrstuvwx'].join('_')], { fetchFn: fakeFetch({}), log: quiet() })).code, 2);
});

test('publishable keys are not sent as a Bearer token', async () => {
  const f = fakeFetch({ [`HEAD ${BASE}/rest/v1/t`]: head('*/*') });
  await run(['--supabase-url', BASE, '--key', 'sb_publishable_abcdefghijklmnopqrstuv', '--tables', 't'], { fetchFn: f, log: quiet() });
  const c = f.calls.find((x) => x.method === 'HEAD');
  assert.equal(c.headers.apikey, 'sb_publishable_abcdefghijklmnopqrstuv');
  assert.equal(c.headers.authorization, undefined);
});

test('--count reports exact rows', async () => {
  const f = fakeFetch({ [`HEAD ${BASE}/rest/v1/leads`]: (init) => head(init.headers.prefer === 'count=exact' ? '0-0/1342' : '0-0/*')() });
  const { report } = await run(['--supabase-url', BASE, '--key', ANON, '--tables', 'leads', '--count'], { fetchFn: f, log: quiet() });
  assert.equal(report.tables[0].rows, 1342);
  assert.match(report.findings.find((x) => x.level === 'critical').detail, /1342 row/);
});

test('network failures are inconclusive, not passes', async () => {
  const f = async (url, init) => {
    if (url.includes('/rest/v1/slow')) throw Object.assign(new Error('The operation was aborted'), { name: 'TimeoutError' });
    return new Response('nope', { status: 404 });
  };
  const { report } = await run(['--supabase-url', BASE, '--key', ANON, '--tables', 'slow'], { fetchFn: f, log: quiet() });
  assert.equal(report.tables[0].state, 'error');
  assert.ok(report.findings.some((x) => x.title.includes('inconclusive')));
});

test('site with no Supabase reference', async () => {
  const f = fakeFetch({ 'GET https://plain.test': text('<html><script src="/a.js"></script></html>'), 'GET https://plain.test/a.js': text('console.log(1)') });
  const { code, report } = await run(['https://plain.test'], { fetchFn: f, log: quiet() });
  assert.equal(code, 0);
  assert.ok(report.findings.some((x) => x.title === 'No Supabase project found'));
});

test('unreachable site is reported, not thrown', async () => {
  const { code, report } = await run(['https://down.test'], { fetchFn: async () => new Response('', { status: 503 }), log: quiet() });
  assert.equal(code, 0);
  assert.ok(report.findings.some((x) => x.title === 'Could not read the site'));
});

test('usage errors', async () => {
  assert.equal((await run([], { log: quiet() })).code, 2);
  assert.equal((await run(['--nope'], { log: quiet() })).code, 2);
  assert.equal((await run(['a.test', '--timeout', '-1'], { log: quiet() })).code, 2);
  assert.equal((await run(['--help'], { log: quiet() })).code, 0);
});

test('json output is valid and masks keys', async () => {
  const log = quiet();
  await run(['https://app.test', '--json'], { fetchFn: leakyApp(), log });
  const parsed = JSON.parse(log.text());
  assert.equal(parsed.project, BASE);
  assert.ok(!log.text().includes(ANON));
});

test('extraction details', () => {
  const e = extract(`a.from( 'leads' ) b.from(\`deals\`) c.storage.from("docs") Array.from("no") Buffer.from("no") d.rpc('do_thing', {})`);
  assert.deepEqual([...e.tables].sort(), ['deals', 'leads']);
  assert.deepEqual([...e.buckets], ['docs']);
  assert.deepEqual([...e.rpcs], ['do_thing']);
  assert.deepEqual(scriptUrls('<script src="/a.js"></script><script src="https://cdn.x/b.js"></script><link rel="modulepreload" href="/c.js">', 'https://s.test/p'),
    ['https://s.test/a.js', 'https://cdn.x/b.js', 'https://s.test/c.js']);
  assert.deepEqual(chunkUrls('import("/assets/x-1.js");"_next/static/chunks/app/page-9.js"', 'https://s.test'),
    ['https://s.test/assets/x-1.js', 'https://s.test/_next/static/chunks/app/page-9.js']);
});
