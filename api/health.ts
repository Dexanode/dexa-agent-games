/** Vercel serverless adapter for the unsigned health check. */
import type { ServerResponse } from 'node:http';
import { healthResponse } from '../src/handler.js';

export default function handler(_req: unknown, res: ServerResponse): void {
  const result = healthResponse();
  res.writeHead(result.status, result.headers);
  res.end(result.body);
}
