/**
 * Raw body capture.
 *
 * The single most common cause of "every webhook fails validation" is a body
 * parser running first: JSON.parse -> JSON.stringify does not round-trip byte
 * for byte, so the HMAC is taken over different bytes than the sender signed.
 * These helpers keep the original Buffer.
 */

import type { IncomingMessage } from 'node:http';

export class BodyTooLargeError extends Error {
  readonly limit: number;
  constructor(limit: number) {
    super(`request body exceeded ${limit} bytes`);
    this.name = 'BodyTooLargeError';
    this.limit = limit;
  }
}

export function readRawBody(req: IncomingMessage, limitBytes = 1024 * 1024): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;

    const fail = (err: Error) => {
      if (settled) return;
      settled = true;
      req.removeAllListeners('data');
      req.removeAllListeners('end');
      req.removeAllListeners('error');
      reject(err);
    };

    req.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > limitBytes) {
        fail(new BodyTooLargeError(limitBytes));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      if (settled) return;
      settled = true;
      resolve(Buffer.concat(chunks));
    });

    req.on('error', fail);
  });
}

/**
 * Express: pass as the `verify` hook so express.json still populates req.body
 * while the untouched bytes stay available on req.rawBody.
 *
 *   app.use('/webhooks/dify', express.json({ verify: captureRawBody }));
 */
export function captureRawBody(req: IncomingMessage & { rawBody?: Buffer }, _res: unknown, buf: Buffer): void {
  req.rawBody = Buffer.from(buf);
}

/**
 * Fetch/Web-standard runtimes (Next.js route handlers, Hono, Trigger.dev's
 * webhook handlers). Read the body as bytes exactly once, before any .json().
 */
export async function rawBodyFromRequest(request: { arrayBuffer(): Promise<ArrayBuffer> }): Promise<Buffer> {
  return Buffer.from(await request.arrayBuffer());
}

export function headersFromFetchHeaders(headers: { forEach(cb: (value: string, key: string) => void): void }): Record<string, string> {
  const out: Record<string, string> = {};
  headers.forEach((value, key) => {
    out[key.toLowerCase()] = value;
  });
  return out;
}
