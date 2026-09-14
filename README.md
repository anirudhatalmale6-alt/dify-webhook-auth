# dify-webhook-auth

Timing-safe HMAC-SHA256 verification for inbound Dify webhooks, plus the harness
that proves it under concurrency.

Zero runtime dependencies — `node:crypto` and `node:http` only. TypeScript is a
dev dependency for type-checking; nothing is bundled or compiled to run.

Requires Node 22.6+ (the scripts use built-in type stripping, so there is no
build step).

## Quick start

```bash
npm install          # typescript + @types/node only
npm test             # 29 unit tests
npm run test:load    # 2000 requests at concurrency 128 against a live server
npm run test:timing  # timing distribution, early-diff vs late-diff signature
npm run typecheck    # tsc --noEmit, strict
```

`npm run verify:all` runs all three in order.

## Usage

```ts
import { verifyWebhook } from './src/verify.ts';

const result = verifyWebhook(rawBody, req.headers, {
  secret: process.env.DIFY_WEBHOOK_SECRET!,
  toleranceSeconds: 300,
});

if (!result.ok) {
  logger.warn('dify webhook rejected', { reason: result.reason });
  return res.status(401).json({ ok: false });
}
```

`result.reason` is a fixed string from a closed set, so it can be a metric label
without cardinality problems:

| reason | meaning |
| --- | --- |
| `missing_signature` | the signature header was absent or blank |
| `malformed_signature` | present but not a parseable 32-byte digest |
| `missing_timestamp` | a replay window is configured and nothing carries the time |
| `malformed_timestamp` | the timestamp was not a positive integer |
| `timestamp_outside_tolerance` | correctly signed but too old or too far ahead — a replay |
| `signature_mismatch` | the digest did not match any configured secret |
| `no_secret_configured` | misconfiguration; fails closed rather than accepting |

## The three things that actually break this in production

**1. The body must be the raw bytes.**

This is the cause of almost every "the signature never validates" report. A body
parser runs first, `JSON.parse` then `JSON.stringify` re-orders keys, changes
number formatting (`1.0` → `1`) and re-encodes unicode escapes, so the HMAC is
taken over different bytes than the sender signed. `src/rawBody.ts` has helpers
for both styles:

```ts
// Express — keeps req.body working AND gives you req.rawBody
import express from 'express';
import { captureRawBody } from './src/rawBody.ts';
app.use('/webhooks/dify', express.json({ verify: captureRawBody }));

// Next.js route handler / Hono / any fetch-style runtime
import { rawBodyFromRequest, headersFromFetchHeaders } from './src/rawBody.ts';
const rawBody = await rawBodyFromRequest(request);        // read bytes FIRST
const headers = headersFromFetchHeaders(request.headers); // then verify
```

There is a test for exactly this (`unicode survives: a re-serialised body would
NOT verify, raw bytes do`) so a future refactor that adds a body parser in front
of the verifier fails the suite instead of failing in production.

**2. The comparison must not short-circuit.**

`crypto.timingSafeEqual` throws when the two buffers differ in length, which
tempts an early `return false` — and that early return leaks the length, and on
some implementations the position of the first differing byte. Here every
candidate is decoded to a fixed 32 bytes before comparison, a wrong-length
candidate is compared against a decoy of the right length so the call costs the
same, and every configured secret is checked with no short-circuit on the first
match.

`npm run test:timing` measures a signature wrong in its **first** byte against
one wrong only in its **last** byte, over 8 independent rounds of 20k calls
each. A single round on a shared machine is meaningless — one GC pause is worth
hundreds of nanoseconds — so what matters is whether the difference has a
consistent sign:

```
round   wrong FIRST byte   wrong LAST byte   difference
1       3115               3125              +10 ns
2       3064               3025              -39 ns
3       3094               3015              -79 ns
4       3145               3034              -111 ns
5       3154               3295              +141 ns
6       3035               3094              +59 ns
7       3005               3014              +9 ns
8       3224               3075              -149 ns

rounds where LAST-byte was slower   4
rounds where FIRST-byte was slower  4
mean difference                     -19.9 ns
spread across rounds                290 ns
```

A short-circuiting comparison would put every round on the same side of zero,
with a gap that grows with the position of the first differing byte. A 4/4 split
and a mean an order of magnitude below the round-to-round spread is what no leak
looks like on a noisy host. Re-run it and the individual numbers will move; the
split staying near even is the result, not any one figure.

This is evidence, not a formal side-channel proof — that needs an isolated host
and a statistical test such as dudect.

**3. A valid signature is not a fresh request.**

A correctly signed payload captured off the wire stays correctly signed forever.
The timestamp is folded into the signed payload as `"<timestamp>.<body>"` and
checked against `toleranceSeconds` (default 300, both directions so a skewed
clock cannot be used to mint far-future requests). Setting `toleranceSeconds: 0`
disables the window but still verifies the HMAC.

For strict once-only delivery you also want an idempotency key — store the
`workflow_run_id` (or the digest itself) in Redis with a TTL of the tolerance
window and drop repeats. Say the word and I will wire that in; it needs a Redis
URL.

## Signature formats accepted

Dify's header layout varies between self-hosted versions, so the parser accepts
every shape rather than betting on one:

```
<hex>                                   bare lowercase hex, timestamp in its own header
sha256=<hex>                            GitHub style
sha256=<base64>                         base64 variant
t=1757000000,v1=<hex>[,v1=<hex>]        Stripe style, timestamp inside the header
```

Header names are configurable (`signatureHeader`, `timestampHeader`) and matched
case-insensitively. Tell me which one your Dify instance actually sends and I
will lock the config down to just that one — accepting fewer formats is strictly
better once we know.

## Key rotation

Pass an array. Every secret is checked, no short-circuit, and `secretIndex` on a
successful result tells you which one matched — so you can watch the old key's
traffic drop to zero before you remove it.

```ts
verifyWebhook(rawBody, headers, { secret: [NEW_SECRET, OLD_SECRET] });
```

## Concurrency harness

`test/load.ts` starts a real HTTP server and fires a mixed population at it:
60% correctly signed, and the rest tampered bodies, wrong secrets, replayed
stale payloads, malformed headers, missing headers and truncated digests. It
asserts on the two numbers that matter — false accepts and false rejects both
zero — and additionally that the downstream handler ran exactly once per
verified request.

```
requests            2000
concurrency         128
wall clock          995 ms
throughput          2010 req/s
latency p50/p95/p99 20.89 / 376.00 / 958.25 ms

signed requests     1200
accepted (202)      1200
handler invoked     1200
rejected (401)      800
  malformed_signature         160
  missing_signature           80
  signature_mismatch          400
  timestamp_outside_tolerance 160

false accepts       0
false rejects       0
```

The latency figures are loopback on a shared build machine with client and
server in the same process, so treat them as a floor, not as production numbers.
The correctness assertions are the point.

## What has not been proved yet

Honest list, so nothing here reads as more than it is:

- Everything above is verified against a locally signed payload. It has **not**
  been run against a live Dify instance — that needs the real webhook secret and
  the confirmed header name.
- The timing measurement is indicative, as described above.
- Replay protection is a time window, not an idempotency store. Two identical
  deliveries inside the window both pass, by design.
