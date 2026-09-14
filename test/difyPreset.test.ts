/**
 * Tests for the confirmed Dify format: lowercase bare hex in x-dify-signature.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';

import { verifyWebhook, buildSignedPayload } from '../src/verify.ts';
import { bodyOnly, withTimestampHeader } from '../src/difyPreset.ts';

const SECRET = 'whsec_dify_9c4e1f7a2b8d0e5364a1c9f2';
const BODY = JSON.stringify({
  event: 'workflow.finished',
  workflow_run_id: '4f1b9c2e-7a3d-4e55-9b21-0c8d6e4a1f77',
  data: { status: 'succeeded' },
});

const NOW_SECONDS = 1_757_000_000;
const now = () => NOW_SECONDS * 1000;

function bareHex(body: string, ts: number | null, secret = SECRET): string {
  return createHmac('sha256', secret).update(buildSignedPayload(body, ts)).digest('hex');
}

// --- bodyOnly: HMAC over the raw body, no timestamp anywhere -----------------

test('bodyOnly accepts a bare lowercase hex signature over the raw body', () => {
  const headers = { 'x-dify-signature': bareHex(BODY, null) };
  const result = verifyWebhook(BODY, headers, bodyOnly(SECRET));
  assert.equal(result.ok, true);
  assert.equal(result.ok && result.scheme, 'hex');
});

test('bodyOnly rejects a tampered body', () => {
  const headers = { 'x-dify-signature': bareHex(BODY, null) };
  const result = verifyWebhook(BODY.replace('succeeded', 'failed'), headers, bodyOnly(SECRET));
  assert.deepEqual(result, { ok: false, reason: 'signature_mismatch' });
});

test('bodyOnly rejects a signature from a different secret', () => {
  const headers = { 'x-dify-signature': bareHex(BODY, null, 'whsec_attacker') };
  assert.equal(verifyWebhook(BODY, headers, bodyOnly(SECRET)).ok, false);
});

test('bodyOnly accepts uppercase hex too (some senders emit it)', () => {
  const headers = { 'x-dify-signature': bareHex(BODY, null).toUpperCase() };
  assert.equal(verifyWebhook(BODY, headers, bodyOnly(SECRET)).ok, true);
});

test('bodyOnly ignores any stray timestamp header rather than failing closed', () => {
  const headers = {
    'x-dify-signature': bareHex(BODY, null),
    'x-dify-timestamp': String(NOW_SECONDS - 99999),
  };
  assert.equal(verifyWebhook(BODY, headers, bodyOnly(SECRET)).ok, true);
});

test('DOCUMENTED GAP: bodyOnly cannot detect a replay', () => {
  // This asserts the limitation so it is visible in the suite rather than only
  // in a comment. An identical delivery an hour later still verifies.
  const headers = { 'x-dify-signature': bareHex(BODY, null) };
  const opts = bodyOnly(SECRET);
  assert.equal(verifyWebhook(BODY, headers, { ...opts, now: () => NOW_SECONDS * 1000 }).ok, true);
  assert.equal(verifyWebhook(BODY, headers, { ...opts, now: () => (NOW_SECONDS + 86_400) * 1000 }).ok, true);
});

// --- withTimestampHeader: replay protection live ----------------------------

test('withTimestampHeader accepts a fresh request signed over timestamp.body', () => {
  const headers = {
    'x-dify-signature': bareHex(BODY, NOW_SECONDS),
    'x-dify-timestamp': String(NOW_SECONDS),
  };
  const result = verifyWebhook(BODY, headers, {
    ...withTimestampHeader(SECRET, 'x-dify-timestamp'),
    now,
  });
  assert.equal(result.ok, true);
});

test('withTimestampHeader rejects the same request replayed an hour later', () => {
  const headers = {
    'x-dify-signature': bareHex(BODY, NOW_SECONDS),
    'x-dify-timestamp': String(NOW_SECONDS),
  };
  const result = verifyWebhook(BODY, headers, {
    ...withTimestampHeader(SECRET, 'x-dify-timestamp'),
    now: () => (NOW_SECONDS + 3600) * 1000,
  });
  assert.deepEqual(result, { ok: false, reason: 'timestamp_outside_tolerance' });
});

test('withTimestampHeader in body mode: rewriting the timestamp defeats the window', () => {
  // Documents exactly why 'timestamp.body' is the preferred sender format. With
  // the signature covering the body alone, the timestamp is unauthenticated and
  // an attacker can move it to now.
  const headers = {
    'x-dify-signature': bareHex(BODY, null),
    'x-dify-timestamp': String(NOW_SECONDS), // attacker-supplied, not signed
  };
  const result = verifyWebhook(BODY, headers, {
    ...withTimestampHeader(SECRET, 'x-dify-timestamp', 'body'),
    now,
  });
  assert.equal(result.ok, true, 'accepted — the timestamp is not covered by the signature');
});

test('withTimestampHeader fails closed when the timestamp header is absent', () => {
  const headers = { 'x-dify-signature': bareHex(BODY, NOW_SECONDS) };
  const result = verifyWebhook(BODY, headers, {
    ...withTimestampHeader(SECRET, 'x-dify-timestamp'),
    now,
  });
  assert.deepEqual(result, { ok: false, reason: 'missing_timestamp' });
});

test('both presets pin the header name to x-dify-signature', () => {
  assert.equal(bodyOnly(SECRET).signatureHeader, 'x-dify-signature');
  assert.equal(withTimestampHeader(SECRET, 'x-dify-timestamp').signatureHeader, 'x-dify-signature');
  // A signature sent under any other header name is not accepted.
  const headers = { 'x-webhook-signature': bareHex(BODY, null) };
  assert.deepEqual(verifyWebhook(BODY, headers, bodyOnly(SECRET)), { ok: false, reason: 'missing_signature' });
});

test('key rotation works through the presets', () => {
  const headers = { 'x-dify-signature': bareHex(BODY, null, 'whsec_old') };
  const result = verifyWebhook(BODY, headers, bodyOnly(['whsec_new', 'whsec_old']));
  assert.equal(result.ok, true);
  assert.equal(result.ok && result.secretIndex, 1);
});
