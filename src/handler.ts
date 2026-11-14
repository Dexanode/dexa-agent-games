/**
 * Transport-agnostic Agent Games request handler.
 *
 * Used identically by the local node:http server (tools/server.ts) and the Vercel
 * serverless adapter (api/agent.ts).
 *
 * Protocol rules enforced here:
 *   - Inbound HMAC verified over the RAW body BEFORE JSON parsing.
 *   - EVERY response (including errors) is signed with the
 *     `x-agent-games-signature` header, HMAC over the raw response body.
 *   - Fail closed: unknown types, bad signatures, broken JSON and internal
 *     errors never produce an approval-shaped answer.
 *   - Missing HMAC secret in env => POSTs are refused (503). The secret is
 *     platform-generated (dashboard "Rotate Secret"); a local placeholder
 *     would silently fail every real verification.
 */
import {
  SIGNATURE_HEADER,
  getHmacSecret,
  signBody,
  verifyBodySignature,
} from './hmac.js';
import { processGatekeeperTask, type GatekeeperTask } from './gatekeeper.js';
import { processStealTurn, type StealTurnEnvelope } from './steal.js';

export interface HandlerRequest {
  method: string;
  path?: string;
  rawBody: string;
  headers: Record<string, string | string[] | undefined>;
}

export interface HandlerResponse {
  status: number;
  body: string;
  headers: Record<string, string>;
}

export const PREFLIGHT_TYPE = 'agent-games.preflight.v1';
export const GATEKEEPER_TYPE = 'agent-games.proof-gatekeeper.v1';

export function healthResponse(): HandlerResponse {
  return {
    status: 200,
    body: JSON.stringify({ ok: true, service: 'dexa-agent-games' }),
    headers: { 'content-type': 'application/json' },
  };
}

function getHeader(
  headers: HandlerRequest['headers'],
  name: string,
): string | undefined {
  const v = headers[name] ?? headers[name.toLowerCase()];
  return Array.isArray(v) ? v[0] : v;
}

function signedJson(
  status: number,
  payload: unknown,
  secret: string | null,
): HandlerResponse {
  const body = JSON.stringify(payload);
  const headers: Record<string, string> = {
    'content-type': 'application/json',
  };
  if (secret) headers[SIGNATURE_HEADER] = signBody(body, secret);
  return { status, body, headers };
}

export async function handleAgentRequest(
  req: HandlerRequest,
): Promise<HandlerResponse> {
  const secret = getHmacSecret();

  // Health is a plain unsigned GET (also used for platform liveness checks).
  if (req.method === 'GET') {
    return healthResponse();
  }

  if (req.method !== 'POST') {
    return signedJson(405, { ok: false, error: 'method_not_allowed' }, secret);
  }

  if (!secret) {
    console.error(
      '[handler] AGENT_GAMES_HMAC_SECRET is not set — refusing POST (fail closed)',
    );
    return {
      status: 503,
      body: JSON.stringify({ ok: false, error: 'server_not_configured' }),
      headers: { 'content-type': 'application/json' },
    };
  }

  // 1. Verify signature over the RAW body before parsing anything.
  const signature = getHeader(req.headers, SIGNATURE_HEADER);
  if (!verifyBodySignature(req.rawBody, signature, secret)) {
    return signedJson(401, { ok: false, error: 'invalid_signature' }, secret);
  }

  // 2. Parse.
  let msg: any;
  try {
    msg = JSON.parse(req.rawBody);
  } catch {
    return signedJson(400, { ok: false, error: 'invalid_json' }, secret);
  }

  // 3. Route.
  try {
    if (msg?.type === PREFLIGHT_TYPE) {
      return signedJson(200, { ok: true, protocolVersion: 'v1' }, secret);
    }

    if (msg?.type === GATEKEEPER_TYPE) {
      const decision = await processGatekeeperTask(msg as GatekeeperTask);
      return signedJson(200, decision, secret);
    }

    if (msg?.eventId === 'steal-the-vfy') {
      const response = await processStealTurn(msg as StealTurnEnvelope);
      return signedJson(200, response, secret);
    }

    return signedJson(400, { ok: false, error: 'unknown_type' }, secret);
  } catch (err) {
    console.error('[handler] processing error:', (err as Error).message);
    return signedJson(500, { ok: false, error: 'internal_error' }, secret);
  }
}
