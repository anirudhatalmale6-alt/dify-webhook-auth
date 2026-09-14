import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, randomBytes } from 'node:crypto';

import {
  verifyWebhook,
  parseSignatureHeader,
  buildSignedPayload,
  safeDigestEqual,
  sign,
  signHeaders,
} from '../src/verify.ts';

const SECRET = 'whsec_test_2f4c9a1b7e0d4a6f8c3b5e7a9d1f2c4b';
const BODY = JSON.stringify({
  event: 'workflow.finished',
  workflow_run_id: '4f1b9c2e-7a3d-4e55-9b21-0c8d6e4a1f77',
  data: { status: 'succeeded', outputs: { asset_key: 'renders/scene-0042.exr' } },
});

/** Fixed clock so nothing in this file depends on the day it runs. */
const NOW_SECONDS = 1_757_000_000;
const now = () => NOW_SECONDS * 1000;

function hex(body: string, ts: number | null, secret = SECRET): string {
  return createHmac('sha256', secret).update(buildSignedPayload(body, ts)).digest('hex');
}

function elementsHeader(body: string, ts = NOW_SECONDS, secret = SECRET) {
  return { 'x-dify-signature': `t=${ts},v1=${hex(body, ts, secret)}` };
}

test('accepts a correctly signed payload (elements scheme)', () => {
  const result = verifyWebhook(BODY, elementsHeader(BODY), { secret: SECRET, now });
  assert.equal(result.ok, true);
  assert.equal(result.ok && result.scheme, 'elements');
  assert.equal(result.ok && result.timestamp, NOW_SECONDS);
});

test('accepts the sha256=<hex> scheme with a separate timestamp header', () => {
  const result = verifyWebhook(BODY, {
    'x-dify-signature': `sha256=${hex(BODY, NOW_SECONDS)}`,
    'x-dify-timestamp': String(NOW_SECONDS),
  }, { secret: SECRET, now });
  assert.equal(result.ok, true);
  assert.equal(result.ok && result.scheme, 'prefixed-hex');
});

test('accepts bare hex with a separate timestamp header', () => {
  const result = verifyWebhook(BODY, {
    'x-dify-signature': hex(BODY, NOW_SECONDS),
    'x-dify-timestamp': String(NOW_SECONDS),
  }, { secret: SECRET, now });
  assert.equal(result.ok, true);
  assert.equal(result.ok && result.scheme, 'hex');
});

test('accepts base64 digests', () => {
  const digest = sign(SECRET, buildSignedPayload(BODY, NOW_SECONDS)).toString('base64');
  const result = verifyWebhook(BODY, {
    'x-dify-signature': `sha256=${digest}`,
    'x-dify-timestamp': String(NOW_SECONDS),
  }, { secret: SECRET, now });
  assert.equal(result.ok, true);
  assert.equal(result.ok && result.scheme, 'prefixed-base64');
});

test('header lookup is case-insensitive and tolerates array values', () => {
  const result = verifyWebhook(BODY, {
    'X-Dify-Signature': [`t=${NOW_SECONDS},v1=${hex(BODY, NOW_SECONDS)}`],
  }, { secret: SECRET, now });
  assert.equal(result.ok, true);
});

test('rejects a tampered body', () => {
  const headers = elementsHeader(BODY);
  const tampered = BODY.replace('scene-0042', 'scene-9999');
  assert.notEqual(tampered, BODY);
  const result = verifyWebhook(tampered, headers, { secret: SECRET, now });
  assert.deepEqual(result, { ok: false, reason: 'signature_mismatch' });
});

test('rejects a single flipped byte in the body', () => {
  const headers = elementsHeader(BODY);
  const body = Buffer.from(BODY, 'utf8');
  body[body.length - 2] ^= 0x01;
  const result = verifyWebhook(body, headers, { secret: SECRET, now });
  assert.deepEqual(result, { ok: false, reason: 'signature_mismatch' });
});

test('rejects a signature made with a different secret', () => {
  const result = verifyWebhook(BODY, elementsHeader(BODY, NOW_SECONDS, 'whsec_wrong'), { secret: SECRET, now });
  assert.deepEqual(result, { ok: false, reason: 'signature_mismatch' });
});

test('rejects a missing signature header', () => {
  const result = verifyWebhook(BODY, {}, { secret: SECRET, now });
  assert.deepEqual(result, { ok: false, reason: 'missing_signature' });
});

test('rejects an empty signature header', () => {
  const result = verifyWebhook(BODY, { 'x-dify-signature': '   ' }, { secret: SECRET, now });
  assert.deepEqual(result, { ok: false, reason: 'missing_signature' });
});

test('rejects a malformed signature without throwing', () => {
  for (const value of ['not-a-signature', 'sha256=zzzz', 'sha256=', 'v1=', 't=123', 'sha1=' + hex(BODY, NOW_SECONDS)]) {
    const result = verifyWebhook(BODY, { 'x-dify-signature': value }, { secret: SECRET, now });
    assert.equal(result.ok, false, `expected rejection for ${value}`);
  }
});

test('a truncated digest is rejected, not crashed on (timingSafeEqual length guard)', () => {
  const short = hex(BODY, NOW_SECONDS).slice(0, 40);
  const result = verifyWebhook(BODY, { 'x-dify-signature': `sha256=${short}`, 'x-dify-timestamp': String(NOW_SECONDS) }, { secret: SECRET, now });
  assert.deepEqual(result, { ok: false, reason: 'malformed_signature' });
});

test('an over-long digest is rejected, not crashed on', () => {
  const long = hex(BODY, NOW_SECONDS) + 'ab';
  const result = verifyWebhook(BODY, { 'x-dify-signature': `sha256=${long}`, 'x-dify-timestamp': String(NOW_SECONDS) }, { secret: SECRET, now });
  assert.deepEqual(result, { ok: false, reason: 'malformed_signature' });
});

test('safeDigestEqual never throws on mismatched lengths', () => {
  const a = randomBytes(32);
  assert.equal(safeDigestEqual(a, Buffer.alloc(0)), false);
  assert.equal(safeDigestEqual(a, randomBytes(16)), false);
  assert.equal(safeDigestEqual(a, randomBytes(64)), false);
  assert.equal(safeDigestEqual(a, Buffer.from(a)), true);
});

test('rejects a replayed payload outside the tolerance window', () => {
  const oldTs = NOW_SECONDS - 3600;
  const result = verifyWebhook(BODY, elementsHeader(BODY, oldTs), { secret: SECRET, now, toleranceSeconds: 300 });
  assert.deepEqual(result, { ok: false, reason: 'timestamp_outside_tolerance' });
});

test('accepts a payload inside the tolerance window, in both directions', () => {
  for (const drift of [-299, -1, 0, 1, 299]) {
    const ts = NOW_SECONDS + drift;
    const result = verifyWebhook(BODY, elementsHeader(BODY, ts), { secret: SECRET, now, toleranceSeconds: 300 });
    assert.equal(result.ok, true, `drift ${drift} should be accepted`);
  }
});

test('rejects a future timestamp beyond tolerance (clock-skew abuse)', () => {
  const result = verifyWebhook(BODY, elementsHeader(BODY, NOW_SECONDS + 3600), { secret: SECRET, now, toleranceSeconds: 300 });
  assert.deepEqual(result, { ok: false, reason: 'timestamp_outside_tolerance' });
});

test('a replay is only rejected because of the window, not by accident', () => {
  // Same bytes, same signature: valid now, invalid once the window passes.
  const ts = NOW_SECONDS;
  const headers = elementsHeader(BODY, ts);
  const opts = { secret: SECRET, toleranceSeconds: 300 };
  assert.equal(verifyWebhook(BODY, headers, { ...opts, now: () => ts * 1000 }).ok, true);
  assert.equal(verifyWebhook(BODY, headers, { ...opts, now: () => (ts + 301) * 1000 }).ok, false);
});

test('fails closed when a replay window is configured but no timestamp arrives', () => {
  const result = verifyWebhook(BODY, { 'x-dify-signature': `sha256=${hex(BODY, null)}` }, { secret: SECRET, now });
  assert.deepEqual(result, { ok: false, reason: 'missing_timestamp' });
});

test('toleranceSeconds: 0 disables the replay check but still verifies the HMAC', () => {
  const ok = verifyWebhook(BODY, { 'x-dify-signature': `sha256=${hex(BODY, null)}` }, { secret: SECRET, now, toleranceSeconds: 0 });
  assert.equal(ok.ok, true);
  const bad = verifyWebhook(BODY, { 'x-dify-signature': `sha256=${hex('other', null)}` }, { secret: SECRET, now, toleranceSeconds: 0 });
  assert.equal(bad.ok, false);
});

test('rejects a non-numeric timestamp header', () => {
  const result = verifyWebhook(BODY, {
    'x-dify-signature': `sha256=${hex(BODY, NOW_SECONDS)}`,
    'x-dify-timestamp': 'yesterday',
  }, { secret: SECRET, now });
  assert.deepEqual(result, { ok: false, reason: 'malformed_timestamp' });
});

test('a millisecond timestamp is normalised to seconds', () => {
  const result = verifyWebhook(BODY, {
    'x-dify-signature': `sha256=${hex(BODY, NOW_SECONDS)}`,
    'x-dify-timestamp': String(NOW_SECONDS * 1000),
  }, { secret: SECRET, now });
  assert.equal(result.ok, true);
});

test('fails closed when no secret is configured', () => {
  assert.deepEqual(verifyWebhook(BODY, elementsHeader(BODY), { secret: '', now }), { ok: false, reason: 'no_secret_configured' });
  assert.deepEqual(verifyWebhook(BODY, elementsHeader(BODY), { secret: [], now }), { ok: false, reason: 'no_secret_configured' });
});

test('key rotation: both the old and the new secret are accepted', () => {
  const oldSecret = 'whsec_old';
  const newSecret = 'whsec_new';
  const opts = { secret: [newSecret, oldSecret], now };
  const viaOld = verifyWebhook(BODY, elementsHeader(BODY, NOW_SECONDS, oldSecret), opts);
  const viaNew = verifyWebhook(BODY, elementsHeader(BODY, NOW_SECONDS, newSecret), opts);
  assert.equal(viaOld.ok, true);
  assert.equal(viaOld.ok && viaOld.secretIndex, 1);
  assert.equal(viaNew.ok, true);
  assert.equal(viaNew.ok && viaNew.secretIndex, 0);
  assert.equal(verifyWebhook(BODY, elementsHeader(BODY, NOW_SECONDS, 'whsec_third'), opts).ok, false);
});

test('multiple v1 elements: one valid digest among decoys is accepted', () => {
  const good = hex(BODY, NOW_SECONDS);
  const decoy = randomBytes(32).toString('hex');
  const header = { 'x-dify-signature': `t=${NOW_SECONDS},v1=${decoy},v1=${good}` };
  assert.equal(verifyWebhook(BODY, header, { secret: SECRET, now }).ok, true);
});

test('an empty body is signed and verified like any other', () => {
  const header = { 'x-dify-signature': `t=${NOW_SECONDS},v1=${hex('', NOW_SECONDS)}` };
  assert.equal(verifyWebhook('', header, { secret: SECRET, now }).ok, true);
  assert.equal(verifyWebhook('x', header, { secret: SECRET, now }).ok, false);
});

test('unicode survives: a re-serialised body would NOT verify, raw bytes do', () => {
  const raw = '{"note":"caf\\u00e9 \\u2014 \\u00e9t\\u00e9","n":1.0}';
  const header = { 'x-dify-signature': `t=${NOW_SECONDS},v1=${hex(raw, NOW_SECONDS)}` };
  assert.equal(verifyWebhook(raw, header, { secret: SECRET, now }).ok, true);

  // This is the classic production failure: parse then re-stringify.
  const reserialised = JSON.stringify(JSON.parse(raw));
  assert.notEqual(reserialised, raw);
  assert.equal(verifyWebhook(reserialised, header, { secret: SECRET, now }).ok, false);
});

test('signHeaders round-trips through verifyWebhook for every scheme', () => {
  for (const scheme of ['elements', 'hex', 'prefixed-hex', 'prefixed-base64'] as const) {
    const headers = signHeaders(BODY, SECRET, { scheme, timestamp: NOW_SECONDS });
    const result = verifyWebhook(BODY, headers, { secret: SECRET, now });
    assert.equal(result.ok, true, `${scheme} should round-trip`);
  }
});

test('parseSignatureHeader returns null rather than throwing on junk', () => {
  for (const junk of ['', '   ', '=', ',', 'v1=', 't=abc,v1=abc', '%%%%']) {
    assert.equal(parseSignatureHeader(junk), null, `expected null for ${JSON.stringify(junk)}`);
  }
});
