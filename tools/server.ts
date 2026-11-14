/**
 * Plain node:http server for local development / self-hosting.
 * Uses the exact same handler as the Vercel adapter.
 *
 * Routes:
 *   GET  /health | /api/health   -> health JSON (unsigned)
 *   POST /agent  | /api/agent    -> Agent Games endpoint (HMAC-signed)
 *
 * Run: npm run build && npm start   (PORT env, default 8787)
 */
import { createServer, type Server } from 'node:http';
import { pathToFileURL } from 'node:url';
import { handleAgentRequest, healthResponse } from '../src/handler.js';

const MAX_BODY_BYTES = 1_000_000; // 1 MB — tasks are small; cap defensively.

export function createAgentServer(): Server {
  return createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost');
    const path = url.pathname;

    try {
      if (req.method === 'GET' && (path === '/health' || path === '/api/health')) {
        const result = healthResponse();
        res.writeHead(result.status, result.headers);
        res.end(result.body);
        return;
      }

      if (req.method === 'POST' && (path === '/agent' || path === '/api/agent')) {
        const chunks: Buffer[] = [];
        let size = 0;
        for await (const chunk of req) {
          const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string);
          size += buf.length;
          if (size > MAX_BODY_BYTES) {
            res.writeHead(413, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ ok: false, error: 'body_too_large' }));
            return;
          }
          chunks.push(buf);
        }
        const rawBody = Buffer.concat(chunks).toString('utf8');
        const result = await handleAgentRequest({
          method: 'POST',
          path,
          rawBody,
          headers: req.headers,
        });
        res.writeHead(result.status, result.headers);
        res.end(result.body);
        return;
      }

      res.writeHead(404, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'not_found' }));
    } catch (err) {
      console.error('[server] error:', (err as Error).message);
      if (!res.headersSent) {
        res.writeHead(500, { 'content-type': 'application/json' });
      }
      res.end(JSON.stringify({ ok: false, error: 'internal_error' }));
    }
  });
}

const isMain =
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href;

if (isMain) {
  const port = Number(process.env.PORT ?? 8787);
  createAgentServer().listen(port, () => {
    console.log(`[server] dexa-agent-games listening on :${port}`);
    console.log('[server] POST /agent (signed) · GET /health');
    if (!process.env.AGENT_GAMES_HMAC_SECRET) {
      console.warn(
        '[server] WARNING: AGENT_GAMES_HMAC_SECRET not set — POSTs will be refused (503)',
      );
    }
  });
}
