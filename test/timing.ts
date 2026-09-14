/**
 * Indicative timing measurement.
 *
 * A naive `a === b` comparison returns as soon as two bytes differ, so a
 * signature that is wrong in its FIRST byte is rejected measurably faster than
 * one that is wrong only in its LAST byte. That difference is what an attacker
 * walks, byte by byte, to forge a signature.
 *
 * This script measures both cases through verifyWebhook over several
 * independent rounds and reports the signed difference per round. On a machine
 * with no leak the difference is dominated by scheduler and GC noise, so its
 * SIGN flips from round to round rather than favouring one case consistently --
 * that sign-flipping is the evidence, not any single round's number.
 *
 * It is evidence, not a formal side-channel proof: that needs a quiet, isolated
 * host and a statistical test such as dudect.
 *
 * Run:  node --experimental-strip-types test/timing.ts [samplesPerRound] [rounds]
 */

import { createHmac, timingSafeEqual } from 'node:crypto';
import { verifyWebhook, buildSignedPayload } from '../src/verify.ts';

const SAMPLES = Number(process.argv[2] ?? 20_000);
const ROUNDS = Number(process.argv[3] ?? 8);
const SECRET = 'whsec_timing_5a8f2c1d9b3e7a04';
const NOW_SECONDS = 1_757_000_000;
const now = () => NOW_SECONDS * 1000;
const BODY = JSON.stringify({ event: 'workflow.finished', run: 'a5f2', data: { status: 'succeeded' } });

const correct = createHmac('sha256', SECRET).update(buildSignedPayload(BODY, NOW_SECONDS)).digest('hex');

function flipNibble(hex: string, index: number): string {
  const flipped = ((parseInt(hex[index], 16) ^ 0x1) & 0xf).toString(16);
  return hex.slice(0, index) + flipped + hex.slice(index + 1);
}

const wrongFirst = flipNibble(correct, 0);
const wrongLast = flipNibble(correct, correct.length - 1);

function measureMedian(signature: string, samples: number): number {
  const headers = { 'x-dify-signature': `t=${NOW_SECONDS},v1=${signature}` };
  const opts = { secret: SECRET, now };
  const timings: number[] = new Array(samples);
  for (let i = 0; i < samples; i++) {
    const start = process.hrtime.bigint();
    verifyWebhook(BODY, headers, opts);
    timings[i] = Number(process.hrtime.bigint() - start);
  }
  timings.sort((a, b) => a - b);
  // The median is used rather than a mean: a single GC pause moves a mean by
  // hundreds of nanoseconds and moves a median by none.
  return timings[timings.length >> 1];
}

// Warm up so JIT tiering does not land inside a measured round.
measureMedian(wrongFirst, 5_000);
measureMedian(wrongLast, 5_000);

console.log('');
console.log('  timing distribution over verifyWebhook  (median nanoseconds per call)');
console.log('  --------------------------------------------------------------------');
console.log(`  samples per case per round   ${SAMPLES}`);
console.log(`  rounds                       ${ROUNDS}`);
console.log('');
console.log('  round   wrong FIRST byte   wrong LAST byte   difference');

const deltas: number[] = [];
for (let round = 0; round < ROUNDS; round++) {
  // Alternate which case goes first so any monotonic drift cancels out.
  const firstLeads = round % 2 === 0;
  const a = firstLeads ? measureMedian(wrongFirst, SAMPLES) : measureMedian(wrongLast, SAMPLES);
  const b = firstLeads ? measureMedian(wrongLast, SAMPLES) : measureMedian(wrongFirst, SAMPLES);
  const firstByte = firstLeads ? a : b;
  const lastByte = firstLeads ? b : a;
  const delta = lastByte - firstByte;
  deltas.push(delta);
  console.log(
    `  ${String(round + 1).padEnd(8)}${String(firstByte).padEnd(19)}${String(lastByte).padEnd(18)}${delta >= 0 ? '+' : ''}${delta} ns`,
  );
}

const positive = deltas.filter((d) => d > 0).length;
const negative = deltas.filter((d) => d < 0).length;
const zero = deltas.filter((d) => d === 0).length;
const mean = deltas.reduce((a, b) => a + b, 0) / deltas.length;
const spread = Math.max(...deltas) - Math.min(...deltas);

console.log('');
console.log(`  rounds where LAST-byte was slower   ${positive}`);
console.log(`  rounds where FIRST-byte was slower  ${negative}`);
console.log(`  rounds identical                    ${zero}`);
console.log(`  mean difference                     ${mean >= 0 ? '+' : ''}${mean.toFixed(1)} ns`);
console.log(`  spread across rounds                ${spread} ns`);
console.log('');
console.log('  A short-circuiting comparison would put every round on the same side of');
console.log('  zero with a difference that grows with the position of the first');
console.log('  differing byte. A sign that flips between rounds, with a mean far below');
console.log('  the round-to-round spread, is what no-leak looks like on a noisy host.');
console.log('');

const a = Buffer.from(correct, 'hex');
console.log(`  timingSafeEqual(correct, correct) = ${timingSafeEqual(a, Buffer.from(correct, 'hex'))}`);
console.log(`  timingSafeEqual(correct, wrong)   = ${timingSafeEqual(a, Buffer.from(wrongLast, 'hex'))}`);
console.log('');
