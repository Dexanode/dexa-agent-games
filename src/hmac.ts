/**
 * HMAC signing / verification for Agent Games platform traffic.
 *
 * ASSUMPTION (verified against https://agentgames.zkverify.io/build on
 * 2026-11-14): the /build page says requests and responses are signed with
 * the header `x-agent-games-signature` over the RAW body, and that the secret
 * comes from the dashboard "Rotate Secret" button — but it does NOT state the
 * HMAC algorithm or digest encoding. We default to HMAC-SHA256 with a hex
 * digest, selectable via AGENT_GAMES_HMAC_ALG=sha256|sha512. If preflight
 * fails with signature errors after registration, this is the first knob to
 * revisit.
 */
import { createHmac, timingSafeEqual } from 'node:crypto';

export const SIGNATURE_HEADER = 'x-agent-games-signature';

export type HmacAlg = 'sha256' | 'sha512';

export function getHmacAlg(): HmacAlg {
  const alg = (process.env.AGENT_GAMES_HMAC_ALG ?? 'sha256').toLowerCase();
  if (alg === 'sha256' || alg === 'sha512') return alg;
  throw new Error(
    `AGENT_GAMES_HMAC_ALG must be "sha256" or "sha512", got "${alg}"`,
  );
}

export function getHmacSecret(): string | null {
  const secret = process.env.AGENT_GAMES_HMAC_SECRET;
  return secret && secret.length > 0 ? secret : null;
}

/** HMAC hex digest over the exact raw body bytes/string. */
export function signBody(rawBody: string | Buffer, secret: string): string {
  return createHmac(getHmacAlg(), secret).update(rawBody).digest('hex');
}

/**
 * Timing-safe verification of an inbound signature against the RAW request
 * body. Must run BEFORE any JSON parsing (spec requirement).
 */
export function verifyBodySignature(
  rawBody: string | Buffer,
  signatureHeader: string | undefined | null,
  secret: string,
): boolean {
  if (!signatureHeader) return false;
  const expected = signBody(rawBody, secret);
  const provided = signatureHeader.trim().toLowerCase();
  const a = Buffer.from(expected, 'utf8');
  const b = Buffer.from(provided, 'utf8');
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}
