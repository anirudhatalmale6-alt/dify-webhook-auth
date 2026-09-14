/**
 * Timing-safe HMAC-SHA256 verification for inbound Dify webhooks.
 *
 * Design notes that matter in production:
 *
 *  1. The signature is computed over the RAW request body. If the body has been
 *     parsed and re-serialised (JSON.stringify(req.body)) the bytes will differ
 *     (key order, whitespace, unicode escaping) and every request will fail.
 *     Capture the raw Buffer before any body parser runs — see rawBody.ts.
 *
 *  2. Comparison never short-circuits. crypto.timingSafeEqual requires equal
 *     length buffers, so a candidate of the wrong length would normally throw
 *     or force an early `return false` that leaks length through timing. We
 *     always perform a compare of the same cost, against a decoy when needed.
 *
 *  3. Multiple secrets are supported for zero-downtime rotation. Every secret
 *     is checked; results are OR-ed without short-circuiting.
 *
 *  4. A timestamp tolerance window turns a captured-and-replayed payload from a
 *     valid request into a rejected one.
 */

import { createHmac, timingSafeEqual, randomBytes } from 'node:crypto';

export type FailureReason =
  | 'missing_signature'
  | 'malformed_signature'
  | 'missing_timestamp'
  | 'malformed_timestamp'
  | 'timestamp_outside_tolerance'
  | 'signature_mismatch'
  | 'no_secret_configured';

export type SignatureScheme = 'hex' | 'prefixed-hex' | 'prefixed-base64' | 'elements';

export type ParsedSignature = {
  scheme: SignatureScheme;
  /** Every candidate digest found in the header. More than one means key rotation. */
  candidates: Buffer[];
  /** Timestamp carried inside the header itself (elements scheme), in seconds. */
  timestamp: number | null;
};

export type VerifyOptions = {
  /** One secret, or several during a rotation. */
  secret: string | Buffer | Array<string | Buffer>;
  /** Header carrying the signature. Default: x-dify-signature */
  signatureHeader?: string;
  /** Header carrying the unix-seconds timestamp, when it is not inside the signature header. */
  timestampHeader?: string;
  /** Replay window in seconds. 0 disables the check entirely. Default: 300 */
  toleranceSeconds?: number;
  /**
   * How the signed payload is assembled.
   *   'auto'           - "<timestamp>.<body>" when a timestamp is present, else "<body>"
   *   'timestamp.body' - always "<timestamp>.<body>"; a missing timestamp is a failure
   *   'body'           - always "<body>"; any timestamp is used only for the replay window
   */
  payloadFormat?: 'auto' | 'timestamp.body' | 'body';
  /** Injectable clock, milliseconds since epoch. Tests pass a fixed value. */
  now?: () => number;
};

export type VerifySuccess = {
  ok: true;
  scheme: SignatureScheme;
  timestamp: number | null;
  /** Index into the configured secret list that matched. Useful during rotation. */
  secretIndex: number;
};

export type VerifyFailure = {
  ok: false;
  reason: FailureReason;
};

export type VerifyResult = VerifySuccess | VerifyFailure;

export type HeaderBag = Record<string, string | string[] | undefined>;

const DIGEST_BYTES = 32; // sha256
const HEX_64 = /^[0-9a-fA-F]{64}$/;
const BASE64_DIGEST = /^[A-Za-z0-9+/]{42,43}={0,2}$/;

/**
 * Per-process key used only for the decoy compare. It never leaves the process
 * and is not a security boundary; it exists so a wrong-length candidate costs
 * the same wall-clock time as a right-length one.
 */
const DECOY = randomBytes(DIGEST_BYTES);

function headerValue(headers: HeaderBag, name: string): string | null {
  const lower = name.toLowerCase();
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() !== lower) continue;
    const raw = headers[key];
    const value = Array.isArray(raw) ? raw[0] : raw;
    if (typeof value !== 'string') return null;
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : null;
  }
  return null;
}

function decodeHex(value: string): Buffer | null {
  if (!HEX_64.test(value)) return null;
  return Buffer.from(value, 'hex');
}

function decodeBase64(value: string): Buffer | null {
  if (!BASE64_DIGEST.test(value)) return null;
  const buf = Buffer.from(value, 'base64');
  return buf.length === DIGEST_BYTES ? buf : null;
}

function decodeDigest(value: string): Buffer | null {
  return decodeHex(value) ?? decodeBase64(value);
}

/**
 * Accepts every shape we have seen in the wild:
 *
 *   <hex>                                  plain lowercase hex
 *   sha256=<hex>                           GitHub style
 *   sha256=<base64>                        base64 variant
 *   t=1700000000,v1=<hex>[,v1=<hex>]       Stripe style, multiple digests allowed
 */
export function parseSignatureHeader(raw: string): ParsedSignature | null {
  const value = raw.trim();

  if (value.includes('=') && value.includes(',')) {
    const parsed = parseElements(value);
    if (parsed) return parsed;
  }

  const eq = value.indexOf('=');
  if (eq > 0 && !value.includes(',')) {
    const algo = value.slice(0, eq).trim().toLowerCase();
    const rest = value.slice(eq + 1).trim();
    if (algo === 'sha256' || algo === 'v1') {
      const hex = decodeHex(rest);
      if (hex) return { scheme: 'prefixed-hex', candidates: [hex], timestamp: null };
      const b64 = decodeBase64(rest);
      if (b64) return { scheme: 'prefixed-base64', candidates: [b64], timestamp: null };
      return null;
    }
    // Single "t=...," style element with no digest is not a usable signature.
    const single = parseElements(value);
    if (single) return single;
    return null;
  }

  const bare = decodeDigest(value);
  if (bare) return { scheme: 'hex', candidates: [bare], timestamp: null };

  return null;
}

function parseElements(value: string): ParsedSignature | null {
  const candidates: Buffer[] = [];
  let timestamp: number | null = null;

  for (const part of value.split(',')) {
    const eq = part.indexOf('=');
    if (eq <= 0) continue;
    const key = part.slice(0, eq).trim().toLowerCase();
    const val = part.slice(eq + 1).trim();
    if (key === 't' || key === 'timestamp') {
      const parsedTs = parseTimestamp(val);
      if (parsedTs !== null) timestamp = parsedTs;
      continue;
    }
    if (key === 'v1' || key === 'sha256' || key === 'signature') {
      const digest = decodeDigest(val);
      if (digest) candidates.push(digest);
    }
  }

  if (candidates.length === 0) return null;
  return { scheme: 'elements', candidates, timestamp };
}

function parseTimestamp(value: string): number | null {
  if (!/^\d{1,19}$/.test(value)) return null;
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) return null;
  // Tolerate milliseconds being sent where seconds were expected.
  return n > 1e12 ? Math.floor(n / 1000) : n;
}

function toSecretList(secret: VerifyOptions['secret']): Array<string | Buffer> {
  if (Array.isArray(secret)) return secret.filter((s) => (typeof s === 'string' ? s.length > 0 : s.length > 0));
  if (typeof secret === 'string') return secret.length > 0 ? [secret] : [];
  return secret.length > 0 ? [secret] : [];
}

/**
 * Constant-time equality for two 32-byte digests. Never throws: a candidate of
 * the wrong length is compared against a decoy so the call costs the same.
 */
export function safeDigestEqual(expected: Buffer, candidate: Buffer): boolean {
  if (candidate.length !== expected.length) {
    timingSafeEqual(expected, DECOY.subarray(0, expected.length));
    return false;
  }
  return timingSafeEqual(expected, candidate);
}

export function sign(secret: string | Buffer, signedPayload: string | Buffer): Buffer {
  return createHmac('sha256', secret).update(signedPayload).digest();
}

/**
 * Build the exact byte string the HMAC is taken over. Exported so the test
 * harness and any outbound caller sign precisely what the verifier checks.
 */
export function buildSignedPayload(rawBody: Buffer | string, timestamp: number | null): Buffer {
  const body = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody, 'utf8');
  if (timestamp === null) return body;
  return Buffer.concat([Buffer.from(`${timestamp}.`, 'utf8'), body]);
}

/**
 * Verify a raw body against the signature headers.
 *
 * `rawBody` MUST be the untouched bytes off the wire.
 */
export function verifyWebhook(
  rawBody: Buffer | string,
  headers: HeaderBag,
  options: VerifyOptions,
): VerifyResult {
  const secrets = toSecretList(options.secret);
  if (secrets.length === 0) return { ok: false, reason: 'no_secret_configured' };

  const signatureHeader = options.signatureHeader ?? 'x-dify-signature';
  const timestampHeader = options.timestampHeader ?? 'x-dify-timestamp';
  const tolerance = options.toleranceSeconds ?? 300;
  const payloadFormat = options.payloadFormat ?? 'auto';
  const nowMs = (options.now ?? Date.now)();

  const rawSignature = headerValue(headers, signatureHeader);
  if (rawSignature === null) return { ok: false, reason: 'missing_signature' };

  const parsed = parseSignatureHeader(rawSignature);
  if (parsed === null) return { ok: false, reason: 'malformed_signature' };

  const rawTimestampHeader = headerValue(headers, timestampHeader);
  let timestamp = parsed.timestamp;
  if (timestamp === null && rawTimestampHeader !== null) {
    timestamp = parseTimestamp(rawTimestampHeader);
    if (timestamp === null) return { ok: false, reason: 'malformed_timestamp' };
  }

  if (payloadFormat === 'timestamp.body' && timestamp === null) {
    return { ok: false, reason: rawTimestampHeader === null ? 'missing_timestamp' : 'malformed_timestamp' };
  }

  if (tolerance > 0) {
    if (timestamp === null) {
      // A replay window was requested but nothing carries the time.
      if (payloadFormat !== 'body') return { ok: false, reason: 'missing_timestamp' };
    } else {
      const driftSeconds = Math.abs(Math.floor(nowMs / 1000) - timestamp);
      if (driftSeconds > tolerance) return { ok: false, reason: 'timestamp_outside_tolerance' };
    }
  }

  const signedPayload = buildSignedPayload(rawBody, payloadFormat === 'body' ? null : timestamp);

  // No short-circuit: every secret against every candidate, then decide.
  let matchedSecret = -1;
  for (let s = 0; s < secrets.length; s++) {
    const expected = sign(secrets[s], signedPayload);
    for (const candidate of parsed.candidates) {
      const equal = safeDigestEqual(expected, candidate);
      if (equal && matchedSecret === -1) matchedSecret = s;
    }
  }

  if (matchedSecret === -1) return { ok: false, reason: 'signature_mismatch' };

  return { ok: true, scheme: parsed.scheme, timestamp, secretIndex: matchedSecret };
}

/** Convenience wrapper for producing the headers an outbound signer would send. */
export function signHeaders(
  rawBody: Buffer | string,
  secret: string | Buffer,
  opts: { timestamp?: number; scheme?: SignatureScheme; signatureHeader?: string; timestampHeader?: string } = {},
): Record<string, string> {
  const timestamp = opts.timestamp ?? Math.floor(Date.now() / 1000);
  const scheme = opts.scheme ?? 'elements';
  const signatureHeader = opts.signatureHeader ?? 'x-dify-signature';
  const timestampHeader = opts.timestampHeader ?? 'x-dify-timestamp';

  if (scheme === 'elements') {
    const digest = sign(secret, buildSignedPayload(rawBody, timestamp)).toString('hex');
    return { [signatureHeader]: `t=${timestamp},v1=${digest}` };
  }

  const digest = sign(secret, buildSignedPayload(rawBody, timestamp));
  const encoded = scheme === 'prefixed-base64' ? digest.toString('base64') : digest.toString('hex');
  const value = scheme === 'hex' ? encoded : `sha256=${encoded}`;
  return { [signatureHeader]: value, [timestampHeader]: String(timestamp) };
}
