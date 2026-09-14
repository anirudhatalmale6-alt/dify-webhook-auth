/**
 * Minimal dependency-free receiver used by the load harness and usable as-is in
 * front of a Trigger.dev task trigger. No framework, so it drops into anything.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { readRawBody, BodyTooLargeError } from './rawBody.ts';
import { verifyWebhook, type VerifyOptions, type VerifyResult } from './verify.ts';

export type WebhookServerOptions = {
  path?: string;
  verify: VerifyOptions;
  bodyLimitBytes?: number;
  /** Called only after the signature has been verified. */
  onVerified?: (payload: Buffer, result: VerifyResult) => void | Promise<void>;
  /** Called on every rejection; wire this to your logger/metrics. */
  onRejected?: (reason: string, req: IncomingMessage) => void;
};

export type Counters = {
  accepted: number;
  rejected: number;
  byReason: Record<string, number>;
};

export function createWebhookServer(options: WebhookServerOptions): { server: Server; counters: Counters } {
  const path = options.path ?? '/webhooks/dify';
  const counters: Counters = { accepted: 0, rejected: 0, byReason: {} };

  const reject = (res: ServerResponse, status: number, reason: string, req: IncomingMessage) => {
    counters.rejected += 1;
    counters.byReason[reason] = (counters.byReason[reason] ?? 0) + 1;
    options.onRejected?.(reason, req);
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: false, reason }));
  };

  const server = createServer((req, res) => {
    void (async () => {
      try {
        const url = req.url ?? '/';
        const pathname = url.split('?')[0];
        if (pathname !== path) {
          res.writeHead(404, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ ok: false, reason: 'not_found' }));
          return;
        }
        if (req.method !== 'POST') {
          reject(res, 405, 'method_not_allowed', req);
          return;
        }

        let rawBody: Buffer;
        try {
          rawBody = await readRawBody(req, options.bodyLimitBytes ?? 1024 * 1024);
        } catch (err) {
          if (err instanceof BodyTooLargeError) {
            reject(res, 413, 'body_too_large', req);
            return;
          }
          reject(res, 400, 'body_read_error', req);
          return;
        }

        const result = verifyWebhook(rawBody, req.headers, options.verify);
        if (!result.ok) {
          reject(res, 401, result.reason, req);
          return;
        }

        counters.accepted += 1;
        await options.onVerified?.(rawBody, result);
        res.writeHead(202, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
      } catch {
        res.writeHead(500, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ ok: false, reason: 'internal_error' }));
      }
    })();
  });

  return { server, counters };
}
