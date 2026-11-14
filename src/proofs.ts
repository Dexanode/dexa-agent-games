/**
 * Groth16 proof generation via snarkjs (Groth16 / BN128, Circom 2.x).
 *
 * Circuit artifacts (downloaded by scripts/download-circuits.sh into
 * circuits/, gitignored):
 *   Gatekeeper: gatekeeper.wasm + gatekeeper_final.zkey
 *     vkHash 0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0
 *   Steal the VFY policy: vfy-policy.wasm + vfy-policy_final.zkey
 *     vkHash 0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047
 *
 * Circuit input mappings were RECOVERED by dictionary attack against the
 * official WASM artifacts (circom_runtime resolves input names by FNV-1a
 * 64-bit hash) and validated end-to-end with real fullProve + verify runs
 * — see CIRCUIT_INPUTS.md for the full evidence.
 *
 * Proof Gatekeeper (template GatekeeperEvaluation): mapping is LIVE below.
 * All 13 inputs are size 1; `salt` is the only private input, everything
 * else (including `decision`) is a public signal. Public-signal order:
 *   [ output, registeredVkHash, proofVkHash, minimum, publicBalance,
 *     expiryBlock, currentBlock, recipient, conditionRecipient,
 *     amount, maxTransfer, decision, taskId ]
 *
 * Steal the VFY (template VfyPolicyProof): input NAMES are also recovered
 * (see the generatePolicyProof comment), but proof generation stays
 * disabled — the commitment Poseidon derivation is unpublished and the
 * strategy params are the user's to set.
 */
import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { keccak256, stringToHex } from 'viem';

export const GATEKEEPER_VK_HASH =
  '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
export const VFY_POLICY_VK_HASH =
  '0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047';

/** BN254 (BN128) scalar field prime. */
export const BN254_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export interface GeneratedProof {
  proof: unknown;
  publicSignals: string[];
}

function circuitsDir(): string {
  if (process.env.CIRCUITS_DIR) return process.env.CIRCUITS_DIR;
  // This file lives in src/ (tsx) or dist/src/ (tsc build, rootDir=".").
  // Walk up from this file's directory until a circuits/ dir is found, so
  // both layouts resolve to <project>/circuits.
  let dir = path.dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 5; i++) {
    const candidate = path.join(dir, 'circuits');
    if (existsSync(candidate)) return candidate;
    dir = path.resolve(dir, '..');
  }
  return path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    '..',
    'circuits',
  );
}

async function fullProve(
  inputs: Record<string, unknown>,
  wasmFile: string,
  zkeyFile: string,
): Promise<GeneratedProof> {
  const snarkjs: any = await import('snarkjs');
  const dir = circuitsDir();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    inputs,
    path.join(dir, wasmFile),
    path.join(dir, zkeyFile),
  );
  return { proof, publicSignals };
}

/**
 * Convert an envelope value to a field element (decimal string).
 * Envelope fields arrive as 0x-hex or decimal strings (or numbers);
 * BigInt() handles all of those. The witness calculator reduces mod the
 * BN254 prime, so no manual reduction is needed here.
 */
function toFieldString(value: unknown): string {
  if (typeof value === 'bigint') return value.toString();
  if (typeof value === 'number') return BigInt(Math.trunc(value)).toString();
  if (typeof value === 'string' && value.trim() !== '') {
    return BigInt(value.trim()).toString();
  }
  throw new Error(`cannot convert value to field element: ${String(value)}`);
}

/** Fresh random salt per proof: 31 random bytes ⇒ always < BN254 prime. */
function freshSalt(): bigint {
  return BigInt(`0x${randomBytes(31).toString('hex')}`) % BN254_PRIME;
}

/**
 * ==========================================================================
 * taskId CONVERSION — THE ONE DOCUMENTED UNKNOWN.
 * ==========================================================================
 * The envelope's `task_id` is a string like "gk_8d31_...". How the PLATFORM
 * maps it to the circuit's `taskId` field element is NOT documented
 * anywhere. The default implemented here is a best-effort heuristic:
 *   1. purely numeric string        -> BigInt(it)
 *   2. trailing segment after the last "_" or "-" is valid hex
 *                                   -> BigInt("0x" + segment)
 *   3. otherwise                    -> keccak256(utf8 string) mod BN254 prime
 *
 * ⚠️ THIS MUST BE CONFIRMED against a real practice-task payload before
 * scored rounds. If the platform expects a different conversion, the
 * platform's own conversion WINS — replace this function (it is isolated
 * for exactly that reason). A wrong taskId does not break local proving
 * (the circuit happily proves any taskId), but the platform re-derives the
 * expected public signals from ITS conversion, so a mismatch means the
 * proof will not match the task it was issued for.
 * ==========================================================================
 */
export function taskIdToField(taskId: string): bigint {
  const s = String(taskId ?? '').trim();
  if (/^\d+$/.test(s)) {
    return BigInt(s) % BN254_PRIME;
  }
  const segment = s.split(/[_-]/).pop() ?? '';
  if (segment !== '' && /^[0-9a-fA-F]+$/.test(segment)) {
    try {
      return BigInt(`0x${segment}`) % BN254_PRIME;
    } catch {
      // fall through to the hash fallback
    }
  }
  return BigInt(keccak256(stringToHex(s))) % BN254_PRIME;
}

/**
 * Map a Proof Gatekeeper task-envelope `input` object to the 13
 * GatekeeperEvaluation circuit inputs (names recovered — CIRCUIT_INPUTS.md
 * section 1). `decision01` is 1 for APPROVE, 0 for REJECT; `salt` is a
 * fresh random field element; `taskIdField` comes from taskIdToField().
 *
 * NOTE: the envelope's `proof_tx` has NO circuit input — it is not proven
 * inside the Gatekeeper circuit.
 */
export function mapGatekeeperInputs(
  envelopeInput: Record<string, unknown>,
  decision01: 0 | 1,
  salt: bigint,
  taskIdField: bigint,
): Record<string, unknown> {
  const input = envelopeInput ?? {};
  return {
    registeredVkHash: toFieldString(input.registered_vk),
    proofVkHash: toFieldString(input.proof_vk),
    minimum: toFieldString(input.minimum),
    publicBalance: toFieldString(input.public_balance),
    expiryBlock: toFieldString(input.expiry_block),
    currentBlock: toFieldString(input.current_block),
    recipient: toFieldString(input.recipient),
    conditionRecipient: toFieldString(input.condition_recipient),
    amount: toFieldString(input.amount),
    maxTransfer: toFieldString(input.max_transfer),
    decision: String(decision01),
    taskId: taskIdField.toString(),
    salt: salt.toString(),
  };
}

export interface GatekeeperEnvelopeLike {
  task_id?: string;
  input: Record<string, unknown>;
  [key: string]: unknown;
}

/**
 * Generate a real Groth16 proof for a Gatekeeper decision.
 *
 * The circuit recomputes the evaluation itself (assert at
 * GatekeeperEvaluation line 102): a genuine task only proves with
 * decision=1, a trap only with decision=0. If the agent's decision does
 * not match the circuit's own evaluation — e.g. the task is
 * circuit-genuine but was REJECTED for an extra-circuit reason (replayed
 * proof_tx, past deadline_at, bad timestamps) — fullProve assert-fails.
 * That failure is EXPECTED in those cases: we catch it, log it, return
 * null (proof omitted), and never throw into the handler.
 */
export async function generateGatekeeperProof(
  envelope: GatekeeperEnvelopeLike,
  decision: 'APPROVE' | 'REJECT' | 0 | 1,
): Promise<GeneratedProof | null> {
  try {
    const decision01: 0 | 1 =
      decision === 'APPROVE' || decision === 1 ? 1 : 0;
    const inputs = mapGatekeeperInputs(
      envelope.input,
      decision01,
      freshSalt(),
      taskIdToField(envelope.task_id ?? ''),
    );
    const started = Date.now();
    const generated = await fullProve(
      inputs,
      'gatekeeper.wasm',
      'gatekeeper_final.zkey',
    );
    console.log(
      `[proofs] gatekeeper fullProve ok (decision=${decision01}) in ${Date.now() - started}ms`,
    );
    return generated;
  } catch (err) {
    console.error(
      '[proofs] gatekeeper fullProve failed (proof omitted):',
      (err as Error).message,
    );
    return null;
  }
}

/**
 * Steal the VFY — input names RECOVERED (CIRCUIT_INPUTS.md section 2),
 * proof generation still blocked.
 *
 * VfyPolicyProof inputs (17 scalars total, getInputSize() == 17):
 *   commitment       (1, public)  envelope strategyCommitment.hash
 *   matchId          (1, public)  match UUID, hyphens stripped, as integer
 *   turnNumber       (1, public)  envelope turn
 *   selfBalance      (1, public)  envelope state.selfBalance
 *   opponentBalance  (1, public)  envelope state.opponentBalance
 *   action           (1, public)  HOLD 0 / FORTIFY 1 / EXTRACT 2
 *   amount           (1, public)  0 for HOLD/FORTIFY
 *   circuitVersion   (1, public)  1 for "v1"
 *   strategyParams   (8, private) the user's committed strategy parameters
 *   salt             (1, private) commitment salt
 *
 * Real blockers (NOT the input mapping):
 *   1. The commitment derivation — how `commitment` is computed from
 *      strategyParams + salt (a Poseidon preimage layout) — is not
 *      published and was not recovered; naive inputs assert-fail at
 *      VfyPolicyProof line 72.
 *   2. The user's strategyParams are unset by design (src/strategy.ts —
 *      the strategy is the user's own; the official guide forbids an AI
 *      from inventing it).
 * Confirm both via the dashboard commitment-registration flow / practice
 * turns before implementing this.
 */
export function mapPolicyInputs(
  _args: Record<string, unknown>,
): Record<string, unknown> | null {
  // Blocked on the unpublished commitment Poseidon derivation and the
  // user's unset strategyParams — see comment above. Returns null.
  return null;
}

export async function generatePolicyProof(
  args: Record<string, unknown>,
): Promise<GeneratedProof | null> {
  const inputs = mapPolicyInputs(args);
  if (!inputs) {
    console.warn(
      '[proofs] vfy-policy proof generation blocked: commitment derivation unpublished + user strategyParams unset — returning no proof',
    );
    return null;
  }
  try {
    return await fullProve(inputs, 'vfy-policy.wasm', 'vfy-policy_final.zkey');
  } catch (err) {
    console.error('[proofs] vfy-policy fullProve failed:', (err as Error).message);
    return null;
  }
}
