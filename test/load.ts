/**
 * Concurrency harness.
 *
 * Fires a mixed population of signed, tampered, stale and malformed requests at
 * a live HTTP receiver and asserts two things that matter more than throughput:
 *
 *   false rejects = 0   every genuinely signed request was accepted
 *   false accepts = 0   nothing else got through
 *
 * Run:  node --experimental-strip-types test/load.ts [total] [concurrency]
 */

import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { createWebhookServer } from '../src/server.ts';
import { signHeaders, sign, buildSignedPayload } from '../src/verify.ts';

const TOTAL = Number(process.argv[2] ?? 2000);
const CONCURRENCY = Number(process.argv[3] ?? 128);
const SECRET = 'whsec_load_' + randomBytes(16).toString('hex');
const TOLERANCE = 300;

type Kind = 'valid' | 'tampered' | 'wrong_secret' | 'stale' | 'malformed' | 'missing' | 'truncated';

type Case = {
  kind: Kind;
  body: string;
  headers: Record<string, string>;
  expectStatus: number;
  expectReason?: string;
};

const MIX: Array<[Kind, number]> = [
  ['valid', 60],
  ['tampered', 10],
  ['wrong_secret', 10],
  ['stale', 8],
  ['malformed', 5],
  ['missing', 4],
  ['truncated', 3],
];

function payload(i: number): string {
  return JSON.stringify({
    event: 'workflow.finished',
    workflow_run_id: randomUUID(),
    sequence: i,
    data: {
      status: 'succeeded',
      outputs: { asset_key: `renders/scene-${String(i).padStart(6, '0')}.exr`, bytes: 1024 * (i % 997) },
    },
  });
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function buildCase(kind: Kind, i: number): Case {
  const body = payload(i);
  const ts = nowSeconds();

  switch (kind) {
    case 'valid':
      return { kind, body, headers: signHeaders(body, SECRET, { timestamp: ts }), expectStatus: 202 };

    case 'tampered': {
      const headers = signHeaders(body, SECRET, { timestamp: ts });
      return { kind, body: body.replace('succeeded', 'FAILED!!'), headers, expectStatus: 401, expectReason: 'signature_mismatch' };
    }

    case 'wrong_secret':
      return {
        kind,
        body,
        headers: signHeaders(body, 'whsec_attacker_' + randomBytes(8).toString('hex'), { timestamp: ts }),
        expectStatus: 401,
        expectReason: 'signature_mismatch',
      };

    case 'stale': {
      // A genuine, correctly signed payload captured and replayed an hour later.
      const oldTs = ts - (TOLERANCE + 3600);
      return { kind, body, headers: signHeaders(body, SECRET, { timestamp: oldTs }), expectStatus: 401, expectReason: 'timestamp_outside_tolerance' };
    }

    case 'malformed':
      return { kind, body, headers: { 'x-dify-signature': 'sha256=' + randomBytes(20).toString('base64url') }, expectStatus: 401, expectReason: 'malformed_signature' };

    case 'missing':
      return { kind, body, headers: {}, expectStatus: 401, expectReason: 'missing_signature' };

    case 'truncated': {
      const digest = sign(SECRET, buildSignedPayload(body, ts)).toString('hex').slice(0, 62);
      return { kind, body, headers: { 'x-dify-signature': `t=${ts},v1=${digest}` }, expectStatus: 401, expectReason: 'malformed_signature' };
    }
  }
}

function buildPopulation(total: number): Case[] {
  const weights = MIX.flatMap(([kind, weight]) => Array.from({ length: weight }, () => kind));
  const cases: Case[] = [];
  for (let i = 0; i < total; i++) {
    cases.push(buildCase(weights[i % weights.length], i));
  }
  // Deterministic interleave so kinds are not grouped: stride through the array.
  const stride = 7;
  const shuffled: Case[] = [];
  for (let offset = 0; offset < stride; offset++) {
    for (let i = offset; i < cases.length; i += stride) shuffled.push(cases[i]);
  }
  return shuffled;
}

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[idx];
}

async function main(): Promise<void> {
  let verifiedCount = 0;
  const { server, counters } = createWebhookServer({
    path: '/webhooks/dify',
    verify: { secret: SECRET, toleranceSeconds: TOLERANCE },
    onVerified: () => {
      verifiedCount += 1;
    },
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('failed to bind');
  const url = `http://127.0.0.1:${address.port}/webhooks/dify`;

  const cases = buildPopulation(TOTAL);
  const latencies: number[] = new Array(cases.length);
  const failures: string[] = [];
  let next = 0;

  const worker = async (): Promise<void> => {
    for (;;) {
      const index = next++;
      if (index >= cases.length) return;
      const testCase = cases[index];
      const started = process.hrtime.bigint();
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...testCase.headers },
        body: testCase.body,
      });
      const bodyText = await res.text();
      latencies[index] = Number(process.hrtime.bigint() - started) / 1e6;

      if (res.status !== testCase.expectStatus) {
        failures.push(`[${testCase.kind}] expected HTTP ${testCase.expectStatus}, got ${res.status} ${bodyText}`);
        continue;
      }
      if (testCase.expectReason) {
        const parsed = JSON.parse(bodyText) as { reason?: string };
        if (parsed.reason !== testCase.expectReason) {
          failures.push(`[${testCase.kind}] expected reason ${testCase.expectReason}, got ${parsed.reason}`);
        }
      }
    }
  };

  const wallStart = process.hrtime.bigint();
  await Promise.all(Array.from({ length: CONCURRENCY }, worker));
  const wallMs = Number(process.hrtime.bigint() - wallStart) / 1e6;

  await new Promise<void>((resolve) => server.close(() => resolve()));

  const expectedValid = cases.filter((c) => c.kind === 'valid').length;
  const sorted = [...latencies].sort((a, b) => a - b);

  console.log('');
  console.log('  concurrency harness');
  console.log('  -------------------');
  console.log(`  requests            ${cases.length}`);
  console.log(`  concurrency         ${CONCURRENCY}`);
  console.log(`  wall clock          ${wallMs.toFixed(0)} ms`);
  console.log(`  throughput          ${((cases.length / wallMs) * 1000).toFixed(0)} req/s`);
  console.log(`  latency p50/p95/p99 ${percentile(sorted, 50).toFixed(2)} / ${percentile(sorted, 95).toFixed(2)} / ${percentile(sorted, 99).toFixed(2)} ms`);
  console.log('');
  console.log(`  signed requests     ${expectedValid}`);
  console.log(`  accepted (202)      ${counters.accepted}`);
  console.log(`  handler invoked     ${verifiedCount}`);
  console.log(`  rejected (401)      ${counters.rejected}`);
  for (const [reason, count] of Object.entries(counters.byReason).sort()) {
    console.log(`    ${reason.padEnd(28)}${count}`);
  }
  console.log('');
  console.log(`  false accepts       ${counters.accepted - expectedValid}`);
  console.log(`  false rejects       ${expectedValid - counters.accepted}`);
  console.log('');

  for (const failure of failures.slice(0, 10)) console.error('  MISMATCH ' + failure);

  assert.equal(failures.length, 0, `${failures.length} request(s) did not behave as expected`);
  assert.equal(counters.accepted, expectedValid, 'accepted count must equal the number of correctly signed requests');
  assert.equal(verifiedCount, expectedValid, 'the downstream handler must run exactly once per verified request');
  assert.equal(counters.rejected, cases.length - expectedValid, 'everything else must be rejected');

  console.log(`  RESULT: PASS - ${expectedValid}/${expectedValid} valid accepted, 0 invalid accepted`);
}

await main();
