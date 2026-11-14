/**
 * End-to-end harness: boots the real local server (dist/tools/server.js) with a
 * test HMAC secret, then exercises it over HTTP with properly signed
 * requests:
 *   - preflight
 *   - bad signature rejection
 *   - Proof Gatekeeper: genuine sample + 5 trap samples + proof replay
 *   - Steal the VFY: one turn, incl. an independently computed
 *     publicInputsHash test vector
 *   - GET /health
 * Every response's `x-agent-games-signature` header is verified against the
 * raw response body.
 *
 * Run via `npm test` (builds first) or directly: `node test/harness.mjs`
 * (requires a prior `npm run build`).
 */
import { spawn } from 'node:child_process';
import { createHmac } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { concat, keccak256, numberToHex } from 'viem';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PORT = 18787;
const BASE = `http://127.0.0.1:${PORT}`;
const SECRET = 'harness-test-secret-not-a-real-one';
const ALG = 'sha256';

const sign = (raw) => createHmac(ALG, SECRET).update(raw).digest('hex');

let passed = 0;
let failed = 0;
function check(name, cond, extra = '') {
  if (cond) {
    passed++;
    console.log(`  PASS ${name}`);
  } else {
    failed++;
    console.log(`  FAIL ${name} ${extra}`);
  }
}

async function postSigned(obj, { badSignature = false } = {}) {
  const raw = JSON.stringify(obj);
  const res = await fetch(`${BASE}/agent`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-agent-games-signature': badSignature ? 'deadbeef'.repeat(16) : sign(raw),
    },
    body: raw,
  });
  const text = await res.text();
  const sig = res.headers.get('x-agent-games-signature');
  let json = null;
  try { json = JSON.parse(text); } catch { /* leave null */ }
  return { status: res.status, text, json, sigValid: sig === sign(text), sigPresent: !!sig };
}

async function waitForHealth(proc, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (proc.exitCode !== null) throw new Error(`server exited early (${proc.exitCode})`);
    try {
      const res = await fetch(`${BASE}/health`);
      if (res.ok) return;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error('server did not become healthy in time');
}

const nowIso = () => new Date().toISOString();
const inTenMinutes = () => new Date(Date.now() + 10 * 60_000).toISOString();

function gatekeeperTask(inputOverrides = {}, taskOverrides = {}) {
  return {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: `gk_${Math.random().toString(36).slice(2, 10)}`,
    mode: 'competition',
    issued_at: nowIso(),
    deadline_at: inTenMinutes(),
    input: {
      registered_vk: '0xVKREGISTERED',
      proof_vk: '0xVKREGISTERED',
      minimum: '1000',
      public_balance: '1460',
      expiry_block: 8430000,
      current_block: 8420000,
      recipient: '0xRecipientAAAA',
      condition_recipient: '0xrecipientaaaa', // case differs on purpose
      amount: '500',
      max_transfer: '1000',
      proof_tx: `0xtx_${Math.random().toString(36).slice(2, 12)}`,
      ...inputOverrides,
    },
    ...taskOverrides,
  };
}

async function main() {
  const proc = spawn('node', ['dist/tools/server.js'], {
    cwd: projectRoot,
    env: {
      ...process.env,
      PORT: String(PORT),
      AGENT_GAMES_HMAC_SECRET: SECRET,
      AGENT_GAMES_HMAC_ALG: ALG,
      // KURIER_API_KEY deliberately unset: decisions must not depend on it.
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  proc.stderr.on('data', (d) => process.stderr.write(`[server] ${d}`));

  try {
    await waitForHealth(proc);

    console.log('health:');
    {
      const res = await fetch(`${BASE}/health`);
      const json = await res.json();
      check('GET /health ok', res.status === 200 && json.ok === true && json.service === 'dexa-agent-games');
    }

    console.log('preflight:');
    {
      const r = await postSigned({
        type: 'agent-games.preflight.v1',
        agent_id: 'agt_harness',
        issued_at: nowIso(),
        nonce: 'abc123',
      });
      check('preflight 200', r.status === 200, `got ${r.status}`);
      check('preflight body', r.json?.ok === true && r.json?.protocolVersion === 'v1');
      check('preflight response signed', r.sigPresent && r.sigValid);
    }

    console.log('signature enforcement:');
    {
      const r = await postSigned(
        { type: 'agent-games.preflight.v1', agent_id: 'agt_x', issued_at: nowIso(), nonce: 'n' },
        { badSignature: true },
      );
      check('bad signature -> 401', r.status === 401, `got ${r.status}`);
      check('401 body error', r.json?.error === 'invalid_signature');
      check('401 response still signed', r.sigPresent && r.sigValid);
    }

    console.log('gatekeeper:');
    const genuine = gatekeeperTask({ proof_tx: '0xtx_GENUINE_1' });
    {
      const r = await postSigned(genuine);
      check('genuine -> 200', r.status === 200, `got ${r.status}`);
      check('genuine -> APPROVE/OK', r.json?.decision === 'APPROVE' && r.json?.reason_code === 'OK',
        JSON.stringify(r.json));
      check('genuine echoes proof_tx', r.json?.proof_tx === '0xtx_GENUINE_1');
      check('genuine response signed', r.sigValid);
    }
    {
      const r = await postSigned(gatekeeperTask({ proof_vk: '0xVKATTACKER' }));
      check('vk mismatch -> REJECT VK_SUBSTITUTION',
        r.json?.decision === 'REJECT' && r.json?.reason_code === 'VK_SUBSTITUTION', JSON.stringify(r.json));
    }
    {
      const r = await postSigned(gatekeeperTask({ public_balance: '999' }));
      check('balance < minimum -> REJECT INSUFFICIENT_BALANCE',
        r.json?.decision === 'REJECT' && r.json?.reason_code === 'INSUFFICIENT_BALANCE', JSON.stringify(r.json));
    }
    {
      const r = await postSigned(gatekeeperTask({ amount: '1500' }));
      check('amount > max -> REJECT AMOUNT_EXCEEDS_MAX',
        r.json?.decision === 'REJECT' && r.json?.reason_code === 'AMOUNT_EXCEEDS_MAX', JSON.stringify(r.json));
    }
    {
      const r = await postSigned(gatekeeperTask({ condition_recipient: '0xSomeoneElse' }));
      check('recipient mismatch -> REJECT RECIPIENT_MISMATCH',
        r.json?.decision === 'REJECT' && r.json?.reason_code === 'RECIPIENT_MISMATCH', JSON.stringify(r.json));
    }
    {
      const r = await postSigned(gatekeeperTask({ current_block: 8430001 }));
      check('current > expiry block -> REJECT EXPIRED',
        r.json?.decision === 'REJECT' && r.json?.reason_code === 'EXPIRED', JSON.stringify(r.json));
    }
    {
      // Same task (same proof_tx) a second time -> replay protection.
      const r = await postSigned(genuine);
      check('replayed proof_tx -> REJECT PROOF_REUSED',
        r.json?.decision === 'REJECT' && r.json?.reason_code === 'PROOF_REUSED', JSON.stringify(r.json));
    }
    {
      const r = await postSigned(gatekeeperTask({}, { deadline_at: new Date(Date.now() - 60_000).toISOString() }));
      check('past deadline -> REJECT EXPIRED_TASK',
        r.json?.decision === 'REJECT' && r.json?.reason_code === 'EXPIRED_TASK', JSON.stringify(r.json));
    }
    {
      const r = await postSigned({ type: 'agent-games.something-else.v9' });
      check('unknown type -> 400 unknown_type', r.status === 400 && r.json?.error === 'unknown_type');
    }

    console.log('steal the vfy:');
    {
      const envelope = {
        protocolVersion: 'v1',
        eventId: 'steal-the-vfy',
        mode: 'competition',
        matchId: '123e4567-e89b-12d3-a456-426614174000',
        turn: 3,
        issuedAt: nowIso(),
        deadlineAt: inTenMinutes(),
        state: {
          selfBalance: '95',
          opponentBalance: '105',
          selfFortifiedUntilTurn: null,
          opponentFortifiedUntilTurn: null,
        },
        strategyCommitment: { hash: `0x${'11'.repeat(32)}` },
        resolverVersion: 'v1',
        nonce: 'turn-nonce-3',
      };
      const r = await postSigned(envelope);
      check('steal -> 200', r.status === 200, `got ${r.status} ${r.text}`);
      check('steal echoes matchId/turn', r.json?.matchId === envelope.matchId && r.json?.turn === 3);
      check('steal action HOLD (no strategy params set)', r.json?.action?.type === 'HOLD', JSON.stringify(r.json?.action));
      check('HOLD has NO amount field', r.json?.action && !('amount' in r.json.action));
      check('steal idempotencyKey present', typeof r.json?.idempotencyKey === 'string' && r.json.idempotencyKey.length > 0);
      check('steal response signed', r.sigValid);

      // Independent test vector: HOLD = code 0, amount 0.
      const word = (n) => numberToHex(BigInt(n), { size: 32 });
      const expected = keccak256(concat([
        word(BigInt(envelope.strategyCommitment.hash)),
        word(BigInt(`0x${envelope.matchId.replace(/-/g, '')}`)),
        word(3n),
        word(95n),
        word(105n),
        word(0n),
        word(0n),
        word(1n),
      ]));
      check('publicInputsHash matches independent vector',
        r.json?.policyProof?.publicInputsHash === expected,
        `got ${r.json?.policyProof?.publicInputsHash} want ${expected}`);
      check('policyProof circuitVersion v1', r.json?.policyProof?.circuitVersion === 'v1');
    }
  } finally {
    proc.kill('SIGTERM');
  }

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('harness error:', err);
  process.exit(1);
});
