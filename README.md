# supabase-exposure-check

What can a stranger reach in your Supabase app? Point this at your live site and find out in about ten seconds.

```bash
npx github:Joyhacks/supabase-exposure-check https://your-app.lovable.app
```

It reads your site's JavaScript the way any visitor's browser does, finds your Supabase project and public key, then checks what that key can actually do. Built for apps made with Lovable, Bolt, Cursor or by hand on Supabase, where RLS is the only thing between your data and the internet.

## What it checks

| Check | Why it matters |
|---|---|
| Supabase `service_role` key in your JavaScript | It bypasses every RLS policy. Anyone can read, change or delete everything. Detected by decoding the key, not guessing |
| Other secrets in your JavaScript | Stripe secret keys, Supabase `sb_secret_`, OpenAI, Anthropic, AWS, GitHub, Slack, SendGrid, Resend |
| Tables readable with the public key | Every table your code queries (plus any listed in the API schema) is tested for anonymous read access |
| Instant signups | Open signup with email confirmation off means "authenticated" policies protect nothing |
| Storage buckets | Whether a stranger can list the files in each bucket your app uses |
| Database functions | Lists every `rpc()` your frontend calls, since each is callable by anyone holding the public key |
| Schema exposure | Whether your table and function names are listable by anyone |

Sample output:

```
[CRITICAL] Anyone can read table "profiles"
   At least one row visible with only the public key. The name suggests personal or business data.
   Fix: Enable RLS and add a policy that scopes reads, for example:
     alter table public.profiles enable row level security;
     create policy "own rows" on public.profiles for select using (auth.uid() = user_id);

[HIGH] Anyone can create a confirmed account instantly
   Email signup is open and email confirmation is off. Any RLS policy that only checks "authenticated" is effectively public.
   Fix: Turn on email confirmation (Authentication > Providers > Email), and write policies that check ownership.

[OK] 7 of 9 table(s) return nothing to an anonymous visitor

Summary: 1 critical, 1 high, 0 medium, 2 info, 1 ok
```

## What it will never do

- **Read your data.** Table checks are `HEAD` requests with `limit=1`. Postgres applies RLS and answers with a header saying whether a row is visible. No row content crosses the wire.
- **Write anything.** No inserts, updates, deletes, signups or function calls. The only `POST` is Storage's file-list endpoint, which only lists.
- **Use a leaked key.** If it finds a `service_role` or secret key, it reports it and keeps using the public key. Pass a privileged key with `--key` and it refuses to run.
- **Print your keys.** Output shows `eyJhbGci...9Xk4`, never the full value.

Only scan apps you own or have permission to test.

## Options

```
supabase-exposure-check <site-url> [options]
supabase-exposure-check --supabase-url https://REF.supabase.co --key <anon key> [options]

  --tables a,b      Also check these tables
  --buckets a,b     Also check these storage buckets
  --count           Exact row counts for readable tables (heavier on big tables)
  --json            Machine-readable output
  --timeout N       Seconds per request (default 15)
```

Exit code is `1` when anything critical or high is found, so it works as a CI gate:

```yaml
- run: npx github:Joyhacks/supabase-exposure-check https://staging.yourapp.com
```

No dependencies. Node 18 or newer.

## Reading the results

**"Anyone can read table X"** isn't always a bug. A product catalogue or blog posts table is often public on purpose. It's a bug when the table holds anything about a specific person or customer, which is why names like `profiles`, `orders` or `messages` are marked critical.

**"Return nothing to an anonymous visitor"** means RLS blocked the read or the table is empty. Either way, a stranger gets nothing today. If a table is empty now, re-run after real data lands.

**Inconclusive** checks (timeouts, unexpected responses) are listed separately. They aren't passes.

## Limits

This checks what an anonymous visitor can reach from outside. It can't see what a logged-in user can reach in other users' rows, whether your Edge Functions check auth, or anything in tables your frontend never references (unless the schema is listable). Treat a clean result as "no open doors from the street", not "secure".

## Want the full check?

For a full launch review (RLS policies tested as real users, Edge Functions, storage, auth flows, payments and secrets across your repo history), I run that as a service. [adeolaforgehq.com](https://adeolaforgehq.com)

Pairs well with [Secret Guard](https://github.com/Joyhacks/secret-guard), which stops secrets reaching your frontend in the first place.

MIT licensed. Built by [Adeola Ilori](https://github.com/Joyhacks).
