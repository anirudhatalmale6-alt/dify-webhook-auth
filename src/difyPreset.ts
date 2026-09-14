/**
 * Presets for the confirmed Dify configuration.
 *
 * Client confirmed 2026-09-14: lowercase bare hex, passed directly in the
 * `x-dify-signature` header. No Redis idempotency store for now.
 *
 * That confirmation leaves ONE thing undecided, and it changes the security
 * properties, so both variants are spelled out here rather than guessed at:
 *
 *   Does the instance ALSO send a timestamp header?
 *
 * A bare hex signature carries no timestamp inside itself. If nothing else on
 * the request carries the time, there is nothing to check a replay window
 * against -- a payload captured off the wire stays valid forever.
 *
 *   withTimestampHeader(...)  use when Dify sends a timestamp header too.
 *                             Replay protection is live. Preferred.
 *
 *   bodyOnly()                use when it does not. The HMAC is still verified
 *                             so forgery and tampering are blocked, but replay
 *                             is NOT. Read the note on that function.
 */

import type { VerifyOptions } from './verify.ts';

const SIGNATURE_HEADER = 'x-dify-signature';

/**
 * Bare hex signature over the raw body alone, with no replay protection.
 *
 * SECURITY NOTE: with no timestamp anywhere on the request there is nothing to
 * anchor a freshness check to, so `toleranceSeconds` is 0 and a captured
 * request can be replayed indefinitely by anyone who saw it in transit. What is
 * still guaranteed: nobody without the secret can forge or alter a payload.
 *
 * Two ways to close the replay gap, in order of preference:
 *   1. have Dify send a timestamp header and switch to withTimestampHeader()
 *   2. keep this, and add an idempotency store keyed on a unique field of the
 *      payload (workflow_run_id) so a repeat is dropped on the second delivery
 */
export function bodyOnly(secret: string | string[]): VerifyOptions {
  return {
    secret,
    signatureHeader: SIGNATURE_HEADER,
    payloadFormat: 'body',
    toleranceSeconds: 0,
  };
}

/**
 * Bare hex signature with a companion timestamp header. Replay protection is
 * active: anything older or newer than `toleranceSeconds` is rejected.
 *
 * `signedOver` must match what the sender hashes:
 *   'timestamp.body' -- HMAC over `${timestamp}.${rawBody}`  (most common)
 *   'body'           -- HMAC over the raw body; the timestamp is used only for
 *                       the freshness check and is not covered by the signature
 *
 * Prefer 'timestamp.body'. With 'body' the timestamp is unauthenticated, so an
 * attacker replaying a captured payload can simply rewrite the header to now
 * and walk straight through the window.
 */
export function withTimestampHeader(
  secret: string | string[],
  timestampHeader: string,
  signedOver: 'timestamp.body' | 'body' = 'timestamp.body',
  toleranceSeconds = 300,
): VerifyOptions {
  return {
    secret,
    signatureHeader: SIGNATURE_HEADER,
    timestampHeader,
    payloadFormat: signedOver,
    toleranceSeconds,
  };
}
