// Pulls everything security-relevant out of a site's HTML and JavaScript:
// the Supabase project, its keys, and the tables, buckets and RPCs the app uses.

const SUPABASE_URL = /https:\/\/([a-z0-9]{20})\.supabase\.(?:co|in)\b/g;
const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g;
const PUBLISHABLE = /\bsb_publishable_[A-Za-z0-9_-]{20,}\b/g;
const IDENT = /^[A-Za-z_][A-Za-z0-9_-]{0,62}$/;

// Server-only secrets that should never appear in a browser bundle.
const SECRETS = [
  { id: 'supabase-secret-key', re: /\bsb_secret_[A-Za-z0-9_-]{20,}\b/g, what: 'Supabase secret API key' },
  { id: 'stripe-live-secret', re: /\b[sr]k_live_[0-9a-zA-Z]{20,}\b/g, what: 'Stripe live secret key' },
  { id: 'stripe-test-secret', re: /\bsk_test_[0-9a-zA-Z]{20,}\b/g, what: 'Stripe test secret key' },
  { id: 'openai-key', re: /\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}\b/g, what: 'OpenAI API key' },
  { id: 'anthropic-key', re: /\bsk-ant-[A-Za-z0-9_-]{32,}\b/g, what: 'Anthropic API key' },
  { id: 'aws-access-key', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, what: 'AWS access key ID' },
  { id: 'github-token', re: /\b(?:ghp|gho|ghs|ghu)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b/g, what: 'GitHub token' },
  { id: 'slack-token', re: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/g, what: 'Slack token' },
  { id: 'sendgrid-key', re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g, what: 'SendGrid API key' },
  { id: 'resend-key', re: /\bre_[A-Za-z0-9]{8}_[A-Za-z0-9]{20,}\b/g, what: 'Resend API key' },
];

export function mask(s) {
  return s.length <= 12 ? '***' : `${s.slice(0, 8)}...${s.slice(-4)}`;
}

export function decodeJwt(token) {
  try {
    return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}

export function extract(text) {
  const out = { projects: new Set(), keys: new Map(), tables: new Set(), buckets: new Set(), rpcs: new Set(), secrets: new Map() };

  for (const m of text.matchAll(SUPABASE_URL)) out.projects.add(m[1]);

  for (const m of text.matchAll(JWT)) {
    const p = decodeJwt(m[0]);
    if (!p || typeof p.role !== 'string') continue;
    // Supabase keys carry role anon/service_role and a ref claim.
    if (!['anon', 'service_role'].includes(p.role)) continue;
    out.keys.set(m[0], { token: m[0], role: p.role, ref: typeof p.ref === 'string' ? p.ref : null, kind: 'jwt' });
    if (typeof p.ref === 'string' && /^[a-z0-9]{20}$/.test(p.ref)) out.projects.add(p.ref);
  }
  for (const m of text.matchAll(PUBLISHABLE)) out.keys.set(m[0], { token: m[0], role: 'anon', ref: null, kind: 'publishable' });

  for (const m of text.matchAll(/\.storage\s*\.\s*from\(\s*["'`]([^"'`]+)["'`]\s*\)/g)) if (IDENT.test(m[1])) out.buckets.add(m[1]);
  for (const m of text.matchAll(/\.from\(\s*["'`]([^"'`]+)["'`]\s*\)/g)) {
    const before = text.slice(Math.max(0, m.index - 12), m.index);
    if (/storage\s*$/.test(before) || /Array\s*$/.test(before) || /Buffer\s*$/.test(before)) continue;
    if (IDENT.test(m[1]) && !out.buckets.has(m[1])) out.tables.add(m[1]);
  }
  for (const m of text.matchAll(/\.rpc\(\s*["'`]([^"'`]+)["'`]/g)) if (IDENT.test(m[1])) out.rpcs.add(m[1]);

  for (const rule of SECRETS) for (const m of text.matchAll(rule.re)) out.secrets.set(m[0], { id: rule.id, what: rule.what, value: m[0] });
  return out;
}

export function merge(a, b) {
  for (const k of ['projects', 'tables', 'buckets', 'rpcs']) for (const v of b[k]) a[k].add(v);
  for (const [k, v] of b.keys) a.keys.set(k, v);
  for (const [k, v] of b.secrets) a.secrets.set(k, v);
  return a;
}

export const empty = () => extract('');
