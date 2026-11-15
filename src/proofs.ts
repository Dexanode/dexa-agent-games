/**
 * Groth16 proof generation via snarkjs (Groth16 / BN128, Circom 2.x).
 *
 * Circuit artifacts (scripts/download-circuits.sh -> circuits/, gitignored):
 *   Gatekeeper: gatekeeper.wasm + gatekeeper_final.zkey
 *     vkHash 0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0
 *   Steal the VFY policy: vfy-policy.wasm + vfy-policy_final.zkey
 *     vkHash 0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047
 *
 * CIRCUIT INPUT RECOVERY (2026-11-14 — full write-up in CIRCUIT_INPUTS.md
 * and FINDINGS.md): circom 2.x WASM does not embed plaintext signal names;
 * the COMPLETE input sets were recovered by probing the witness calculator's
 * getInputSignalSize() with FNV-1a name hashes over candidate dictionaries:
 *
 *   GatekeeperEvaluation (13 input components, all size 1):
 *     registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
 *     currentBlock, recipient, conditionRecipient, amount, maxTransfer,
 *     taskId, decision, salt
 *   VfyPolicyProof (17 input components):
 *     commitment, matchId, turnNumber, selfBalance, opponentBalance,
 *     action, amount, circuitVersion, salt (all size 1),
 *     strategyParams (size 8)
 *
 * GATEKEEPER: VERIFIED end-to-end locally — fullProve with genuine and trap
 * samples succeeds, proofs verify with groth16.verify, the circuit enforces
 * decision == recomputed verdict (decision: 1 = APPROVE, 0 = REJECT), and
 * `salt` is the only private input (publicSignals = [Poseidon evaluation
 * hash, ...12 public inputs]).
 *
 * STEAL: input mapping implemented; proving additionally requires the
 * user's committed strategy (strategyParams[8] + salt). Experimentally,
 * commitment = Poseidon(strategyParams..., salt) is strongly indicated
 * (it is the only tried arrangement whose failure moves past the
 * commitment assert), but the circuit also enforces the policy itself, so
 * proofs with arbitrary params assert-fail and safely degrade to "no
 * proof" here. Strategy remains user-owned (src/strategy.ts).
 */
import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { keccak256, toHex } from 'viem';

export const GATEKEEPER_VK_HASH =
  '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
export const VFY_POLICY_VK_HASH =
  '0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047';

/** BN128 (BN254) scalar field prime. */
const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export interface GeneratedProof {
  proof: unknown;
  publicSignals: string[];
}

function circuitsDir(): string {
  if (process.env.CIRCUITS_DIR) return process.env.CIRCUITS_DIR;
  // dist/src/proofs.js and src (dev) both sit two levels below project root.
  const here = path.dirname(fileURLToPath(import.meta.url));
  return path.resolve(here, '..', '..', 'circuits');
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
 * Encode an envelope value as a BN128 field element (decimal string).
 * Accepts decimal strings/numbers and 0x-hex strings (vk hashes, addresses).
 * Returns null for anything else — we do NOT invent encodings for values
 * whose field representation is unknown (task_id is the exception, see
 * taskIdToField below).
 */
export function toFieldElement(v: unknown): string | null {
  try {
    if (typeof v === 'number' && Number.isFinite(v)) {
      return (BigInt(Math.trunc(v)) % FIELD_PRIME).toString();
    }
    if (typeof v === 'bigint') return (v % FIELD_PRIME).toString();
    if (typeof v === 'string') {
      const s = v.trim();
      if (/^0x[0-9a-fA-F]+$/.test(s)) return (BigInt(s) % FIELD_PRIME).toString();
      if (/^[0-9]+$/.test(s)) return (BigInt(s) % FIELD_PRIME).toString();
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Convert an envelope `task_id` string to the circuit's `taskId` field
 * element. DOCUMENTED HEURISTIC (the platform does not publish this
 * mapping; confirm against a practice-task payload before scored rounds):
 *   1. pure decimal string        -> that integer
 *   2. 0x-hex string              -> that integer
 *   3. otherwise take the trailing segment after the last '_' or '-'; if
 *      it is hex, use it as hex ("gk_8d31_ab12" -> 0xab12)
 *   4. last resort: keccak256 of the string, reduced mod the field prime
 */
export function taskIdToField(taskId: string): bigint {
  const s = String(taskId).trim();
  if (/^[0-9]+$/.test(s)) return BigInt(s) % FIELD_PRIME;
  if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s) % FIELD_PRIME;
  const segments = s.split(/[_\-]/).filter((x) => x.length > 0);
  const last = segments[segments.length - 1];
  if (last && /^[0-9a-fA-F]+$/.test(last)) {
    return BigInt('0x' + last) % FIELD_PRIME;
  }
  return BigInt(keccak256(toHex(s))) % FIELD_PRIME;
}

/** Fresh random field element — used as the Gatekeeper `salt` (private). */
function randomFieldElement(): string {
  return (BigInt('0x' + randomBytes(31).toString('hex')) % FIELD_PRIME).toString();
}

// ---------------------------------------------------------------------------
// Proof Gatekeeper
// ---------------------------------------------------------------------------

export interface GatekeeperProofTask {
  task_id: string;
  input: Record<string, unknown>;
}

/**
 * Map a gatekeeper task + the agent's decision to GatekeeperEvaluation
 * circuit inputs. Returns null when any non-taskId value cannot be encoded
 * confidently. `decision` is fed as an input (1 = APPROVE, 0 = REJECT) —
 * the circuit recomputes the verdict and asserts equality, so a wrong
 * decision makes fullProve throw (caught by the caller -> proof omitted).
 * `salt` is agent-chosen randomness (the circuit's only private input; it
 * appears nowhere in the envelope, so it cannot be platform-supplied).
 */
export function mapGatekeeperInputs(
  task: GatekeeperProofTask,
  decision: 'APPROVE' | 'REJECT',
): Record<string, unknown> | null {
  const i = task.input;
  const mapped: Record<string, unknown> = {
    registeredVkHash: toFieldElement(i.registered_vk),
    proofVkHash: toFieldElement(i.proof_vk),
    minimum: toFieldElement(i.minimum),
    publicBalance: toFieldElement(i.public_balance),
    expiryBlock: toFieldElement(i.expiry_block),
    currentBlock: toFieldElement(i.current_block),
    recipient: toFieldElement(i.recipient),
    conditionRecipient: toFieldElement(i.condition_recipient),
    amount: toFieldElement(i.amount),
    maxTransfer: toFieldElement(i.max_transfer),
    taskId: taskIdToField(task.task_id).toString(),
    decision: decision === 'APPROVE' ? '1' : '0',
    salt: randomFieldElement(),
  };
  if (Object.values(mapped).some((v) => v === null)) return null;
  return mapped;
}

export type GatekeeperProofAttempt =
  | { status: 'ok'; generated: GeneratedProof }
  /** The circuit's own evaluation disagrees with `decision` (assert). */
  | { status: 'assert' }
  /** Inputs not field-encodable, or proving failed for a non-circuit reason. */
  | { status: 'unavailable' };

/**
 * Like generateGatekeeperProof, but reports WHY no proof was produced so
 * the caller can distinguish "the circuit disagrees with our decision"
 * (an assert failure inside GatekeeperEvaluation) from infrastructure
 * problems (missing artifacts, unencodable inputs, ...). Only the assert
 * class is a verdict on the decision itself.
 */
export async function attemptGatekeeperProof(
  task: GatekeeperProofTask,
  decision: 'APPROVE' | 'REJECT',
): Promise<GatekeeperProofAttempt> {
  const inputs = mapGatekeeperInputs(task, decision);
  if (!inputs) {
    console.warn(
      '[proofs] gatekeeper inputs not field-encodable — returning no proof',
    );
    return { status: 'unavailable' };
  }
  try {
    const generated = await fullProve(
      inputs,
      'gatekeeper.wasm',
      'gatekeeper_final.zkey',
    );
    return { status: 'ok', generated };
  } catch (err) {
    const message = (err as Error).message ?? '';
    console.error('[proofs] gatekeeper fullProve failed:', message);
    return /assert failed/i.test(message)
      ? { status: 'assert' }
      : { status: 'unavailable' };
  }
}

export async function generateGatekeeperProof(
  task: GatekeeperProofTask,
  decision: 'APPROVE' | 'REJECT' = 'APPROVE',
): Promise<GeneratedProof | null> {
  const attempt = await attemptGatekeeperProof(task, decision);
  return attempt.status === 'ok' ? attempt.generated : null;
}

// ---------------------------------------------------------------------------
// Steal the VFY policy proof
// ---------------------------------------------------------------------------

export interface PolicyProofArgs {
  commitmentHash: string;
  matchId: string;
  turn: number;
  selfBalance: string;
  opponentBalance: string;
  actionCode: number;
  amount: number;
  /** The user's 8 strategy params (decimal/hex strings or numbers). */
  strategyParams: readonly unknown[] | null;
  /** The user's commitment salt (decimal/hex string or number). */
  salt: unknown;
}

/**
 * Map a steal turn to VfyPolicyProof circuit inputs. Returns null unless
 * the user's strategy is configured (strategyParams must be exactly 8
 * field-encodable values and a salt must be present) — the circuit proves
 * compliance with the COMMITTED strategy, so there is nothing meaningful
 * to prove before the user commits one.
 * ASSUMPTION: matchId is encoded as the uuid's hex (hyphens stripped) —
 * the same encoding the official publicInputsHash formula uses.
 */
export function mapPolicyInputs(
  args: PolicyProofArgs,
): Record<string, unknown> | null {
  if (!args.strategyParams || args.strategyParams.length !== 8) return null;
  const params = args.strategyParams.map(toFieldElement);
  if (params.some((p) => p === null)) return null;

  const mapped: Record<string, unknown> = {
    commitment: toFieldElement(args.commitmentHash),
    matchId: toFieldElement('0x' + args.matchId.replace(/-/g, '')),
    turnNumber: toFieldElement(args.turn),
    selfBalance: toFieldElement(args.selfBalance),
    opponentBalance: toFieldElement(args.opponentBalance),
    action: toFieldElement(args.actionCode),
    amount: toFieldElement(args.amount),
    circuitVersion: '1',
    salt: toFieldElement(args.salt),
    strategyParams: params,
  };
  if (
    Object.entries(mapped).some(
      ([k, v]) => k !== 'strategyParams' && v === null,
    )
  ) {
    return null;
  }
  return mapped;
}

export async function generatePolicyProof(
  args: PolicyProofArgs,
): Promise<GeneratedProof | null> {
  const inputs = mapPolicyInputs(args);
  if (!inputs) {
    console.warn(
      '[proofs] vfy-policy proof skipped — user strategy (strategyParams[8] + salt) not configured',
    );
    return null;
  }
  try {
    return await fullProve(inputs, 'vfy-policy.wasm', 'vfy-policy_final.zkey');
  } catch (err) {
    // Expected until the user's REAL committed params are in place: the
    // circuit asserts the played action follows the committed policy.
    console.error('[proofs] vfy-policy fullProve failed:', (err as Error).message);
    return null;
  }
}
