// Read-only checks against a Supabase project, using only the public
// (anon / publishable) key. Nothing here writes data or reads row contents.
//
// Never pass a service_role or secret key to these functions: using a leaked
// privileged key is accessing data you were not given. The CLI refuses to.

const UA = 'supabase-exposure-check (+https://github.com/Joyhacks/supabase-exposure-check)';

function headers(key, extra = {}) {
  const h = { apikey: key, 'user-agent': UA, ...extra };
  // Legacy JWT keys go in Authorization too. New publishable keys must not.
  if (key.startsWith('eyJ')) h.authorization = `Bearer ${key}`;
  return h;
}

async function call(fetchFn, url, init, timeoutMs) {
  try {
    const res = await fetchFn(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
    return res;
  } catch (e) {
    return { ok: false, status: 0, error: e.name === 'TimeoutError' ? 'timed out' : e.message, headers: new Map(), text: async () => '', json: async () => null };
  }
}

const hdr = (res, name) => (res.headers && typeof res.headers.get === 'function' ? res.headers.get(name) : null);

/** Auth settings are public by design. Signups that need no email confirmation
 *  mean "authenticated" policies protect nothing from a stranger. */
export async function checkAuth(fetchFn, base, key, timeoutMs) {
  const res = await call(fetchFn, `${base}/auth/v1/settings`, { headers: headers(key) }, timeoutMs);
  if (!res.ok) return { ok: false, status: res.status };
  const s = await res.json().catch(() => null);
  if (!s) return { ok: false, status: res.status };
  const providers = Object.entries(s.external || {}).filter(([, on]) => on === true).map(([p]) => p);
  return {
    ok: true,
    signupOpen: s.disable_signup !== true,
    autoconfirm: s.mailer_autoconfirm === true,
    phoneAutoconfirm: s.sms_autoconfirm === true,
    providers,
  };
}

/** The REST root returns the OpenAPI schema when it is exposed to the anon role. */
export async function listSchema(fetchFn, base, key, timeoutMs) {
  const res = await call(fetchFn, `${base}/rest/v1/`, { headers: headers(key, { accept: 'application/openapi+json' }) }, timeoutMs);
  if (!res.ok) return { exposed: false, status: res.status, tables: [], rpcs: [] };
  const spec = await res.json().catch(() => null);
  if (!spec || typeof spec !== 'object') return { exposed: false, status: res.status, tables: [], rpcs: [] };
  const tables = new Set();
  const rpcs = new Set();
  for (const p of Object.keys(spec.paths || {})) {
    const m = p.match(/^\/rpc\/(.+)$/);
    if (m) rpcs.add(m[1]);
    else if (p !== '/' && /^\/[\w-]+$/.test(p)) tables.add(p.slice(1));
  }
  for (const d of Object.keys(spec.definitions || {})) tables.add(d);
  return { exposed: tables.size + rpcs.size > 0, status: res.status, tables: [...tables], rpcs: [...rpcs] };
}

/**
 * Can an anonymous visitor read any row of this table?
 * HEAD with limit=1: Postgres applies RLS, and the response carries only a
 * Content-Range header ("0-0/*" means at least one visible row, "*\/*" none).
 * No row data is transferred. With count=true it asks for an exact count.
 */
export async function checkTable(fetchFn, base, key, table, timeoutMs, { count = false } = {}) {
  const extra = count ? { prefer: 'count=exact' } : {};
  const res = await call(fetchFn, `${base}/rest/v1/${encodeURIComponent(table)}?select=*&limit=1`, { method: 'HEAD', headers: headers(key, extra) }, timeoutMs);
  if (res.status === 0) return { table, state: 'error', detail: res.error };
  if (res.status === 401 || res.status === 403) return { table, state: 'denied' };
  if (res.status === 404) return { table, state: 'not_found' };
  if (!res.ok) return { table, state: 'error', detail: `HTTP ${res.status}` };
  const range = hdr(res, 'content-range');
  if (!range) return { table, state: 'unknown', detail: 'no Content-Range header' };
  const [span, total] = range.split('/');
  const visible = span !== '*';
  const rows = total && total !== '*' ? Number(total) : null;
  return { table, state: visible ? 'readable' : 'no_rows', rows };
}

/** Bucket list and file listing, as an anonymous visitor would see them. */
export async function listBuckets(fetchFn, base, key, timeoutMs) {
  const res = await call(fetchFn, `${base}/storage/v1/bucket`, { headers: headers(key) }, timeoutMs);
  if (!res.ok) return { visible: false, buckets: [] };
  const list = await res.json().catch(() => null);
  if (!Array.isArray(list)) return { visible: false, buckets: [] };
  return { visible: list.length > 0, buckets: list.map((b) => ({ name: b.name || b.id, public: b.public === true })) };
}

export async function checkBucket(fetchFn, base, key, bucket, timeoutMs) {
  const res = await call(fetchFn, `${base}/storage/v1/object/list/${encodeURIComponent(bucket)}`, {
    method: 'POST',
    headers: headers(key, { 'content-type': 'application/json' }),
    body: JSON.stringify({ prefix: '', limit: 1, offset: 0 }),
  }, timeoutMs);
  if (!res.ok) return { bucket, state: res.status === 0 ? 'error' : 'denied', detail: res.error };
  const list = await res.json().catch(() => null);
  if (!Array.isArray(list)) return { bucket, state: 'unknown' };
  return { bucket, state: list.length ? 'listable' : 'empty_or_denied' };
}
