# supabase-exposure-check

Checks a live Supabase-backed site from the outside, using only what any visitor's browser already has: the page's JavaScript and the public anon key in it.

```bash
npx github:Joyhacks/supabase-exposure-check https://your-app.example.com
```

I wrote this after reviewing a run of Lovable and Cursor-built apps where the same few problems kept coming up: tables readable by anyone, a `service_role` key in the bundle, and signups with no email confirmation, which turns every "authenticated users only" policy into "anyone". All of those are visible from the browser, so they can be checked without access to the project.

## What it checks

1. Reads the HTML and every script it loads (following lazy-loaded chunks for Vite and Next.js builds) and pulls out the Supabase URL, keys, and the table, bucket and RPC names used in `.from()`, `.storage.from()` and `.rpc()` calls.
2. Decodes any Supabase JWT it finds. A `service_role` key in client code is reported as critical. It also looks for other server secrets: Stripe, OpenAI, Anthropic, AWS, GitHub, Slack, SendGrid, Resend, and Supabase `sb_secret_` keys.
3. Reads `/auth/v1/settings` to see whether signup is open and email confirmation is off.
4. Tests each table for anonymous read access.
5. Tries to list the files in each storage bucket.
6. Lists RPC functions the frontend calls, since each one can be called directly with the anon key.

## Output

From the test fixture in `test/`, which simulates a typical Lovable app:

```
[CRITICAL] Anyone can read table "profiles"
   At least one row visible with only the public key. The name suggests personal or business data.
   Fix: Check that RLS is on and that no select policy is open to everyone (using (true) is the usual culprit). Then scope reads, for example:
     alter table public.profiles enable row level security;
     create policy "own rows" on public.profiles for select using (auth.uid() = user_id);

[HIGH] Anyone can create a confirmed account instantly
   Email signup is open and email confirmation is off. Any RLS policy that only checks "authenticated" is effectively public.

[HIGH] Anyone can read table "services"
   At least one row visible with only the public key. If this is meant to be public (products, blog posts), this is fine.

[MEDIUM] Anyone can list files in bucket "avatars"
   A stranger can enumerate every file name, and download files if the bucket is public.

[OK] 2 of 4 table(s) return nothing to an anonymous visitor
   bookings, reviews

Summary: 1 critical, 2 high, 1 medium, 1 info, 1 ok
```

Exit code is 1 if anything is critical or high, so it can gate a deploy:

```yaml
- run: npx github:Joyhacks/supabase-exposure-check https://staging.example.com
```

## How it stays read-only

Table checks are `HEAD` requests with `limit=1`. PostgREST applies RLS and answers with a `Content-Range` header: `0-0/*` means at least one row is visible, `*/*` means none. No row data is transferred.

The only `POST` is Storage's list endpoint, which lists file names. There are no inserts, updates, deletes, signups or RPC calls.

If the scan finds a `service_role` or secret key, it reports it and carries on with the anon key. It refuses to start if you pass a privileged key with `--key`. Keys are masked in all output.

Only run it against apps you own or have permission to test.

## Options

```
supabase-exposure-check <site-url>
supabase-exposure-check --supabase-url https://<ref>.supabase.co --key <anon key>

  --tables a,b     extra tables to check
  --buckets a,b    extra buckets to check
  --count          exact row counts for readable tables (slower on large tables)
  --json           JSON output
  --timeout N      seconds per request, default 15
```

Node 18 or newer, no dependencies.

## Limitations

It only sees what an anonymous visitor can reach. It won't find a logged-in user reading another user's rows, an Edge Function missing an auth check, or tables the frontend never references (unless the REST schema is exposed, in which case it lists them too). "Returns nothing" can also mean the table is empty, so re-run after real data lands.

A clean result means nothing is open to strangers. It isn't a security review.

## Development

```bash
node --test test/*.test.mjs
```

The tests run the CLI against a fake network (`test/cli.test.mjs`) and check that it never sends a leaked key, never issues anything but `HEAD` against tables, and never prints a full key.

## License

MIT. Written by [Adeola Ilori](https://github.com/Joyhacks). See also [secret-guard](https://github.com/Joyhacks/secret-guard), which catches these keys before they reach the frontend.
