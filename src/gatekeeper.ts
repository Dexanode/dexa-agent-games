/**
 * Proof Gatekeeper — deterministic decision logic (NO LLM in the final call).
 *
 * Envelope (type "agent-games.proof-gatekeeper.v1"):
 *   input: { registered_vk, proof_vk, minimum, public_balance, expiry_block,
 *            current_block, recipient, condition_recipient, amount,
 *            max_transfer, proof_tx }
 *
 * APPROVE only if ALL checks pass; otherwise REJECT with a reason_code.
 * Check order and reason codes follow the starter spec; codes marked
 * "(our choice)" are named by us where the spec described the condition
 * without naming a code.
 *
 * Scoring context (starter prompt): +12 correct, −6 approve a trap,
 * −3 reject a valid task, −2 timeout/offline, −2 proof fails. An omitted or
 * invalid proof on an otherwise-provable task costs points, so on APPROVE we
 * try to attach a real Groth16 proof + public_signals and submit via Kurier;
 * if proof generation is unavailable (see src/proofs.ts TODO) the decision
 * is still returned without the proof fields.
 */
import { generateGatekeeperProof, GATEKEEPER_VK_HASH } from './proofs.js';
import { submitProofAndWaitFinalized } from './kurier.js';

export interface GatekeeperInput {
  registered_vk: string;
  proof_vk: string;
  minimum: string;
  public_balance: string;
  expiry_block: number;
  current_block: number;
  recipient: string;
  condition_recipient: string;
  amount: string;
  max_transfer: string;
  proof_tx: string;
  [key: string]: unknown;
}

export interface GatekeeperTask {
  type: 'agent-games.proof-gatekeeper.v1';
  task_id: string;
  mode?: string;
  issued_at?: string;
  deadline_at?: string;
  input: GatekeeperInput;
  [key: string]: unknown;
}

export interface GatekeeperResponse {
  decision: 'APPROVE' | 'REJECT';
  reason_code: string;
  proof_tx: string;
  proof?: unknown;
  public_signals?: string[];
  proof_reference?: string;
}

/**
 * In-memory replay set of proof_tx values already consumed.
 * NOTE: serverless cold starts reset this — acceptable for v1 (the platform
 * also tracks proof references); a durable store is a future upgrade.
 */
const seenProofTx = new Set<string>();

function reject(reason_code: string, proof_tx: string): GatekeeperResponse {
  return { decision: 'REJECT', reason_code, proof_tx };
}

function safeBigInt(v: unknown): bigint | null {
  try {
    if (typeof v === 'number') return BigInt(Math.trunc(v));
    if (typeof v === 'string' && v.trim() !== '') return BigInt(v);
    return null;
  } catch {
    return null;
  }
}

/**
 * Pure, synchronous evaluation of the seven spec checks, in order.
 * Exported separately so it can be unit-tested without I/O.
 */
export function evaluateGatekeeper(
  task: GatekeeperTask,
  now: Date = new Date(),
): GatekeeperResponse {
  const input = task.input ?? ({} as GatekeeperInput);
  const proofTx = typeof input.proof_tx === 'string' ? input.proof_tx : '';

  // Fail closed on structurally broken input.
  if (!input || typeof input !== 'object' || !proofTx) {
    return reject('INVALID_INPUT', proofTx); // (our choice)
  }

  // 1. Verification-key substitution: the proof must be under the registered vk.
  if (
    typeof input.proof_vk !== 'string' ||
    typeof input.registered_vk !== 'string' ||
    input.proof_vk.toLowerCase() !== input.registered_vk.toLowerCase()
  ) {
    return reject('VK_SUBSTITUTION', proofTx);
  }

  // 2. Balance meets the proven minimum.
  const balance = safeBigInt(input.public_balance);
  const minimum = safeBigInt(input.minimum);
  if (balance === null || minimum === null) {
    return reject('INVALID_INPUT', proofTx); // (our choice)
  }
  if (balance < minimum) {
    return reject('INSUFFICIENT_BALANCE', proofTx); // (our choice)
  }

  // 3. Transfer amount within the allowed maximum.
  const amount = safeBigInt(input.amount);
  const maxTransfer = safeBigInt(input.max_transfer);
  if (amount === null || maxTransfer === null) {
    return reject('INVALID_INPUT', proofTx); // (our choice)
  }
  if (amount > maxTransfer) {
    return reject('AMOUNT_EXCEEDS_MAX', proofTx);
  }

  // 4. Recipient matches the conditioned recipient (case-insensitive).
  if (
    typeof input.recipient !== 'string' ||
    typeof input.condition_recipient !== 'string' ||
    input.recipient.toLowerCase() !== input.condition_recipient.toLowerCase()
  ) {
    return reject('RECIPIENT_MISMATCH', proofTx);
  }

  // 5. Proof/condition not expired on-chain.
  if (
    typeof input.current_block !== 'number' ||
    typeof input.expiry_block !== 'number' ||
    input.current_block > input.expiry_block
  ) {
    return reject('EXPIRED', proofTx);
  }

  // 6. Proof reference must not have been used before (replay protection).
  //    Recorded only once a task has passed checks 1–5, i.e. the proof was
  //    actually presented as valid evidence.
  if (seenProofTx.has(proofTx)) {
    return reject('PROOF_REUSED', proofTx);
  }
  seenProofTx.add(proofTx);

  // 7. Task still within its validity window (deadline not passed).
  //    Missing/unparseable deadline fails closed.
  const deadline = task.deadline_at ? Date.parse(task.deadline_at) : NaN;
  if (Number.isNaN(deadline) || now.getTime() > deadline) {
    return reject('EXPIRED_TASK', proofTx); // (our choice)
  }
  if (task.issued_at) {
    const issued = Date.parse(task.issued_at);
    // 5-minute clock-skew allowance; a task "from the future" is suspect.
    if (Number.isNaN(issued) || issued - now.getTime() > 5 * 60_000) {
      return reject('EXPIRED_TASK', proofTx); // (our choice)
    }
  }

  return { decision: 'APPROVE', reason_code: 'OK', proof_tx: proofTx };
}

/**
 * Full task processing: evaluate -> on APPROVE, attempt proof generation and
 * (when KURIER_API_KEY is set) Kurier submission to zkVerify. Always returns
 * a decision object; never throws for task-level problems (fail closed).
 */
export async function processGatekeeperTask(
  task: GatekeeperTask,
): Promise<GatekeeperResponse> {
  const response = evaluateGatekeeper(task);
  if (response.decision !== 'APPROVE') return response;

  // On provable tasks the response should carry our own Groth16 proof +
  // public_signals. Generation is stubbed until circuit inputs are mapped
  // (src/proofs.ts TODO) — in that case proof fields are omitted, which the
  // platform scores as a proof miss but keeps the decision.
  const generated = await generateGatekeeperProof(
    task.input as unknown as Record<string, unknown>,
  );
  if (!generated) return response;

  response.proof = generated.proof;
  response.public_signals = generated.publicSignals;

  const kurierKey = process.env.KURIER_API_KEY;
  if (kurierKey) {
    const result = await submitProofAndWaitFinalized({
      proof: generated.proof,
      publicSignals: generated.publicSignals,
      vk: GATEKEEPER_VK_HASH,
      apiKey: kurierKey,
    });
    if (result?.finalized) {
      // ASSUMPTION: jobId doubles as the on-chain proof reference pointer.
      response.proof_reference = result.jobId;
    } else {
      console.error(
        '[gatekeeper] Kurier submission did not finalize; returning decision with proof attached',
      );
    }
  }
  return response;
}

/** Test helper: clear the replay set between harness runs. */
export function _resetSeenProofTx(): void {
  seenProofTx.clear();
}
