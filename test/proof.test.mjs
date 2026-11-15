/**
 * Real Groth16 proof tests for Proof Gatekeeper (separate from the main
 * harness — proving takes seconds per task).
 *
 *   1. Genuine envelope, decision APPROVE -> generateGatekeeperProof
 *      returns a proof; snarkjs groth16.verify(exported vk) == true;
 *      publicSignals has length 13 and decision (index 11) == "1".
 *   2. Trap envelope (proof_vk != registered_vk), decision REJECT ->
 *      proof verifies, decision == "0".
 *   3. Same genuine envelope through the real HTTP handler -> response
 *      JSON carries `decision: "APPROVE"`, `proof` and `public_signals`.
 *
 * Run via `npm run test:proof` (builds first). Requires the circuit
 * artifacts in circuits/ (npm run download-circuits).
 */
import { spawn } from 'node:child_process';
import { createHmac } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const snarkjs = createRequire(import.meta.url)('snarkjs');
import {
  attemptGatekeeperProof,
  generateGatekeeperProof,
  taskIdToField,
} from '../dist/src/proofs.js';
import {
  evaluateGatekeeper,
  processGatekeeperTask,
  proveGatekeeperDecision,
} from '../dist/src/gatekeeper.js';

const projectRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
);
const CIRCUITS = path.join(projectRoot, 'circuits');

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

// Full-size hex values, invented consistently for this test.
// (Both vk fields use the real gatekeeper vkHash as the "registered" vk;
// the trap case overrides proof_vk with a different full-size value.)
const VK = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const VK_OTHER = '0x1111111111111111111111111111111111111111111111111111111111111111';
const RECIPIENT = '0x1234567890abcdef1234567890abcdef12345678';

function genuineEnvelope(inputOverrides = {}) {
  return {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: 'gk_8d31_ab12',
    mode: 'competition',
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 10 * 60_000).toISOString(),
    input: {
      registered_vk: VK,
      proof_vk: VK,
      minimum: '1000',
      public_balance: '1460',
      expiry_block: 8430000,
      current_block: 8420000,
      recipient: RECIPIENT,
      condition_recipient: RECIPIENT,
      amount: '500',
      max_transfer: '1000',
      proof_tx: '0xaabbccddeeff00112233445566778899aabbccddeeff00112233445566778899',
      ...inputOverrides,
    },
  };
}

const PORT = 18788;
const BASE = `http://127.0.0.1:${PORT}`;
const SECRET = 'proof-test-secret-not-a-real-one';
const sign = (raw) =>
  createHmac('sha256', SECRET).update(raw).digest('hex');

async function waitForHealth(proc, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (proc.exitCode !== null) {
      throw new Error(`server exited early (${proc.exitCode})`);
    }
    try {
      const res = await fetch(`${BASE}/health`);
      if (res.ok) return;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error('server did not become healthy in time');
}

async function main() {
  const vk = await snarkjs.zKey.exportVerificationKey(
    path.join(CIRCUITS, 'gatekeeper_final.zkey'),
  );
  check('verification key exported, nPublic = 13', vk.nPublic === 13, `got ${vk.nPublic}`);

  console.log('taskId conversion (documented heuristic):');
  check(
    'taskIdToField("gk_8d31_ab12") uses trailing hex segment 0xab12',
    taskIdToField('gk_8d31_ab12') === 0xab12n,
    `got ${taskIdToField('gk_8d31_ab12')}`,
  );

  console.log('gatekeeper proof — genuine / APPROVE:');
  {
    const started = Date.now();
    const generated = await generateGatekeeperProof(genuineEnvelope(), 'APPROVE');
    const elapsed = Date.now() - started;
    console.log(`  fullProve (genuine) took ${elapsed}ms`);
    check('genuine APPROVE -> proof generated', generated !== null);
    if (generated) {
      check(
        'publicSignals length 13',
        generated.publicSignals.length === 13,
        `got ${generated.publicSignals.length}: ${JSON.stringify(generated.publicSignals)}`,
      );
      check(
        'publicSignals[11] (decision) == "1"',
        generated.publicSignals[11] === '1',
        `got ${generated.publicSignals[11]}`,
      );
      const ok = await snarkjs.groth16.verify(
        vk,
        generated.publicSignals,
        generated.proof,
      );
      check('genuine proof verifies locally', ok === true);
    }
  }

  console.log('gatekeeper proof — trap (vk mismatch) / REJECT:');
  {
    const started = Date.now();
    const generated = await generateGatekeeperProof(
      genuineEnvelope({ proof_vk: VK_OTHER }),
      'REJECT',
    );
    const elapsed = Date.now() - started;
    console.log(`  fullProve (trap) took ${elapsed}ms`);
    check('trap REJECT -> proof generated', generated !== null);
    if (generated) {
      check(
        'publicSignals length 13',
        generated.publicSignals.length === 13,
        `got ${generated.publicSignals.length}`,
      );
      check(
        'publicSignals[11] (decision) == "0"',
        generated.publicSignals[11] === '0',
        `got ${generated.publicSignals[11]}`,
      );
      const ok = await snarkjs.groth16.verify(
        vk,
        generated.publicSignals,
        generated.proof,
      );
      check('trap proof verifies locally', ok === true);
    }
  }

  console.log('boundary semantics (audit 2026-11-15, tools/audit-boundaries.mjs):');
  {
    let n = 0;
    const tx = () => '0x' + String(++n).padStart(64, 'f');
    const eqExpiry = evaluateGatekeeper(
      genuineEnvelope({ current_block: 8430000, proof_tx: tx() }),
    );
    check(
      'evaluate: current == expiry -> REJECT EXPIRED (strict <)',
      eqExpiry.decision === 'REJECT' && eqExpiry.reason_code === 'EXPIRED',
      JSON.stringify(eqExpiry),
    );
    const amtEq = await generateGatekeeperProof(
      genuineEnvelope({ amount: '1000' }),
      'APPROVE',
    );
    check('circuit: amount == max_transfer proves APPROVE', amtEq !== null);
    const balEq = await generateGatekeeperProof(
      genuineEnvelope({ public_balance: '1000' }),
      'APPROVE',
    );
    check('circuit: balance == minimum proves APPROVE', balEq !== null);
    const expEqR = await generateGatekeeperProof(
      genuineEnvelope({ current_block: 8430000 }),
      'REJECT',
    );
    check('circuit: current == expiry proves REJECT', expEqR !== null);
    const expEqA = await generateGatekeeperProof(
      genuineEnvelope({ current_block: 8430000 }),
      'APPROVE',
    );
    check('circuit: current == expiry cannot prove APPROVE', expEqA === null);
  }

  console.log('attemptGatekeeperProof statuses:');
  {
    const okA = await attemptGatekeeperProof(genuineEnvelope(), 'APPROVE');
    check('genuine + APPROVE -> status ok', okA.status === 'ok', okA.status);
    const assertA = await attemptGatekeeperProof(genuineEnvelope(), 'REJECT');
    check(
      'genuine + REJECT -> status assert',
      assertA.status === 'assert',
      assertA.status,
    );
  }

  console.log('prove-or-flip (proveGatekeeperDecision):');
  {
    const genuine = genuineEnvelope();
    const forced = {
      decision: 'REJECT',
      reason_code: 'INSUFFICIENT_BALANCE',
      proof_tx: genuine.input.proof_tx,
    };
    const flipped = await proveGatekeeperDecision(genuine, forced);
    check(
      'flip: genuine + forced in-circuit REJECT -> APPROVE/OK',
      flipped.response.decision === 'APPROVE' &&
        flipped.response.reason_code === 'OK',
      JSON.stringify(flipped.response),
    );
    check(
      'flip: proof attached, decision signal == "1"',
      flipped.generated !== null &&
        flipped.generated.publicSignals[11] === '1',
    );

    const trapEnv = genuineEnvelope({
      recipient: '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
    });
    const forcedA = {
      decision: 'APPROVE',
      reason_code: 'OK',
      proof_tx: trapEnv.input.proof_tx,
    };
    const flippedT = await proveGatekeeperDecision(trapEnv, forcedA);
    check(
      'flip: trap + forced APPROVE -> REJECT/CIRCUIT_EVALUATION',
      flippedT.response.decision === 'REJECT' &&
        flippedT.response.reason_code === 'CIRCUIT_EVALUATION',
      JSON.stringify(flippedT.response),
    );
    check(
      'flip: trap proof attached, decision signal == "0"',
      flippedT.generated !== null &&
        flippedT.generated.publicSignals[11] === '0',
    );

    const forcedX = {
      decision: 'REJECT',
      reason_code: 'PROOF_REUSED',
      proof_tx: genuine.input.proof_tx,
    };
    const notFlipped = await proveGatekeeperDecision(genuine, forcedX);
    check(
      'no flip: extra-circuit REJECT stays REJECT, no proof',
      notFlipped.response.decision === 'REJECT' &&
        notFlipped.response.reason_code === 'PROOF_REUSED' &&
        notFlipped.generated === null,
      JSON.stringify(notFlipped.response),
    );
  }

  console.log('kurier wait is bounded (response latency fix 2026-11-16):');
  {
    // A bogus key makes the Kurier submit fail fast; a zero wait makes it
    // abort immediately. Either way the DECISION must come back quickly
    // with the proof attached — the response never blocks on Kurier.
    process.env.KURIER_API_KEY = 'bogus-test-key-not-real';
    try {
      const started = Date.now();
      const resp = await processGatekeeperTask(
        genuineEnvelope({
          proof_tx:
            '0x1111111111111111111111111111111111111111111111111111111111111111',
        }),
      );
      const elapsed = Date.now() - started;
      check(
        'bogus kurier key -> APPROVE with proof attached',
        resp.decision === 'APPROVE' && resp.proof != null,
        JSON.stringify(resp).slice(0, 200),
      );
      check(
        `bogus kurier key -> fast response (${elapsed}ms < 20000ms)`,
        elapsed < 20_000,
      );

      process.env.KURIER_WAIT_MS = '0';
      const started0 = Date.now();
      const resp0 = await processGatekeeperTask(
        genuineEnvelope({
          proof_tx:
            '0x2222222222222222222222222222222222222222222222222222222222222222',
        }),
      );
      const elapsed0 = Date.now() - started0;
      check(
        'KURIER_WAIT_MS=0 -> APPROVE with proof attached',
        resp0.decision === 'APPROVE' && resp0.proof != null,
        JSON.stringify(resp0).slice(0, 200),
      );
      check(
        `KURIER_WAIT_MS=0 -> fast response (${elapsed0}ms < 20000ms)`,
        elapsed0 < 20_000,
      );
    } finally {
      delete process.env.KURIER_API_KEY;
      delete process.env.KURIER_WAIT_MS;
    }
  }

  console.log('gatekeeper proof — through the HTTP handler:');
  {
    const proc = spawn('node', ['dist/tools/server.js'], {
      cwd: projectRoot,
      env: {
        ...process.env,
        PORT: String(PORT),
        AGENT_GAMES_HMAC_SECRET: SECRET,
        AGENT_GAMES_HMAC_ALG: 'sha256',
        // KURIER_API_KEY deliberately unset.
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    proc.stderr.on('data', (d) => process.stderr.write(`[server] ${d}`));
    try {
      await waitForHealth(proc);
      const envelope = genuineEnvelope();
      const raw = JSON.stringify(envelope);
      const res = await fetch(`${BASE}/agent`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-agent-games-signature': sign(raw),
        },
        body: raw,
      });
      const text = await res.text();
      let json = null;
      try {
        json = JSON.parse(text);
      } catch {
        /* leave null */
      }
      check('handler -> 200', res.status === 200, `got ${res.status}: ${text}`);
      check(
        'handler -> APPROVE/OK',
        json?.decision === 'APPROVE' && json?.reason_code === 'OK',
        text,
      );
      check(
        'handler response includes proof',
        json?.proof != null && typeof json.proof === 'object',
        text.slice(0, 200),
      );
      check(
        'handler response includes public_signals (13)',
        Array.isArray(json?.public_signals) && json.public_signals.length === 13,
        text.slice(0, 200),
      );
      check(
        'handler public_signals decision == "1"',
        json?.public_signals?.[11] === '1',
        JSON.stringify(json?.public_signals),
      );
      check(
        'handler echoes proof_tx',
        json?.proof_tx === envelope.input.proof_tx,
      );
    } finally {
      proc.kill('SIGTERM');
    }
  }

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('proof test error:', err);
  process.exit(1);
});
