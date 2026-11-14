/**
 * Vercel serverless adapter for the agent endpoint.
 * Register the FULL deployed path (e.g. https://<project>.vercel.app/api/agent)
 * as the agent endpoint in the Agent Games dashboard.
 *
 * bodyParser is disabled so we receive the RAW body — required for HMAC
 * verification over the exact bytes the platform signed.
 */
import type { IncomingMessage, ServerResponse } from 'node:http';
import { handleAgentRequest } from '../src/handler.js';

export const config = { api: { bodyParser: false } };

async function readRawBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string));
  }
  return Buffer.concat(chunks).toString('utf8');
}

export default async function handler(
  req: IncomingMessage & { method?: string; url?: string },
  res: ServerResponse,
): Promise<void> {
  const rawBody = req.method === 'POST' ? await readRawBody(req) : '';
  const result = await handleAgentRequest({
    method: req.method ?? 'GET',
    path: req.url,
    rawBody,
    headers: req.headers,
  });
  res.writeHead(result.status, result.headers);
  res.end(result.body);
}
