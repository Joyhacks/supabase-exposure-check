// Fetches a site's HTML and the JavaScript it loads, following chunk
// references one level deep so lazily loaded routes are covered too.
import { extract, merge, empty } from './bundle.mjs';

const MAX_SCRIPTS = 40;
const MAX_BYTES = 6_000_000;

export async function get(fetchFn, url, timeoutMs) {
  const res = await fetchFn(url, {
    headers: { 'user-agent': 'supabase-exposure-check (+https://github.com/Joyhacks/supabase-exposure-check)' },
    redirect: 'follow',
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`${url} returned HTTP ${res.status}`);
  const text = await res.text();
  return text.length > MAX_BYTES ? text.slice(0, MAX_BYTES) : text;
}

export function scriptUrls(html, base) {
  const urls = new Set();
  const add = (u) => {
    try {
      const abs = new URL(u, base);
      if (abs.protocol === 'https:' || abs.protocol === 'http:') urls.add(abs.href);
    } catch { /* ignore bad urls */ }
  };
  for (const m of html.matchAll(/<script\b[^>]*\bsrc=["']([^"']+)["']/gi)) add(m[1]);
  for (const m of html.matchAll(/<link\b[^>]*\brel=["'](?:modulepreload|preload)["'][^>]*\bhref=["']([^"']+\.m?js[^"']*)["']/gi)) add(m[1]);
  for (const m of html.matchAll(/<link\b[^>]*\bhref=["']([^"']+\.m?js[^"']*)["'][^>]*\brel=["'](?:modulepreload|preload)["']/gi)) add(m[1]);
  return [...urls];
}

// Chunk paths referenced inside a bundle (Vite /assets, Next /_next/static).
export function chunkUrls(js, base) {
  const urls = new Set();
  for (const m of js.matchAll(/["'`](\/?(?:assets|_next\/static\/chunks)\/[\w./-]+?\.js)["'`]/g)) {
    try {
      urls.add(new URL(m[1].startsWith('/') ? m[1] : '/' + m[1], base).href);
    } catch { /* ignore */ }
  }
  return [...urls];
}

export async function crawl(fetchFn, siteUrl, { timeoutMs = 15000, log = () => {} } = {}) {
  const html = await get(fetchFn, siteUrl, timeoutMs);
  const found = merge(empty(), extract(html));
  const origin = new URL(siteUrl).origin;
  const queue = scriptUrls(html, siteUrl);
  const seen = new Set();
  let fetched = 0;
  const errors = [];

  while (queue.length && fetched < MAX_SCRIPTS) {
    const url = queue.shift();
    if (seen.has(url)) continue;
    seen.add(url);
    try {
      const js = await get(fetchFn, url, timeoutMs);
      fetched++;
      merge(found, extract(js));
      if (new URL(url).origin === origin) for (const c of chunkUrls(js, origin)) if (!seen.has(c)) queue.push(c);
    } catch (e) {
      errors.push(`${url}: ${e.message}`);
    }
  }
  log(`Read ${fetched} script(s) from ${origin}${queue.length ? ` (stopped at ${MAX_SCRIPTS})` : ''}.`);
  return { found, scripts: fetched, errors };
}
