/**
 * Steal the VFY — turn handling.
 *
 * Turn envelope (no `type` field; identified by eventId "steal-the-vfy"):
 *   { protocolVersion, eventId, mode, matchId, turn, issuedAt, deadlineAt,
 *     state: { selfBalance, opponentBalance, selfFortifiedUntilTurn,
 *              opponentFortifiedUntilTurn },
 *     strategyCommitment: { hash }, resolverVersion, nonce }
 *
 * Response: echo matchId + turn, declare ONE action, attach policy proof
 * material, agentTimestamp and a unique-per-turn idempotencyKey.
 *
 * Actions:
 *   HOLD    — no `amount` field AT ALL (schema rejects it, even 0)
 *   FORTIFY — cost 2, blocks up to 6, also NO `amount` field
 *   EXTRACT — the only action with `amount`, amount ≤ 10
 *
 * publicInputsHash: keccak256 over the concatenation of 8 fields, each
 * encoded as numberToHex(value, { size: 32 }) big-endian:
 *   1 strategyCommitment.hash (as BigInt)
 *   2 matchId with hyphens stripped, parsed as hex BigInt
 *   3 turn
 *   4 selfBalance
 *   5 opponentBalance
 *   6 action code (HOLD=0, FORTIFY=1, EXTRACT=2)
 *   7 amount (0 for HOLD/FORTIFY)
 *   8 1 (circuitVersion "v1")
 *
 * Strategy itself is USER-OWNED — see src/strategy.ts. With no strategy
 * params configured, the agent plays HOLD.
 */
import { randomUUID } from 'node:crypto';
import { concat, keccak256, numberToHex } from 'viem';
import { decideAction, type StealAction, type StealState } from './strategy.js';
import { generatePolicyProof } from './proofs.js';

export interface StealTurnEnvelope {
  protocolVersion: string;
  eventId: 'steal-the-vfy';
  mode?: string;
  matchId: string;
  turn: number;
  issuedAt?: string;
  deadlineAt?: string;
  state: {
    selfBalance: string;
    opponentBalance: string;
    selfFortifiedUntilTurn: number | null;
    opponentFortifiedUntilTurn: number | null;
  };
  strategyCommitment: { hash: string };
  resolverVersion?: string;
  nonce?: string;
  [key: string]: unknown;
}

export interface StealResponse {
  matchId: string;
  turn: number;
  action: { type: string; amount?: number };
  policyProof: {
    circuitVersion: 'v1';
    proof?: unknown;
    public_signals?: string[];
    proofReference?: string;
    publicInputsHash: string;
  };
  agentTimestamp: string;
  idempotencyKey: string;
}

export const ACTION_CODES: Record<StealAction['type'], number> = {
  HOLD: 0,
  FORTIFY: 1,
  EXTRACT: 2,
};

const word = (n: bigint): `0x${string}` => numberToHex(n, { size: 32 });

/**
 * Pure function — computes the policy publicInputsHash exactly as the
 * platform does (field order matters; see header).
 */
export function computePublicInputsHash(
  envelope: StealTurnEnvelope,
  action: StealAction,
): `0x${string}` {
  const amount =
    action.type === 'EXTRACT' ? BigInt(action.amount) : 0n;
  const fields: bigint[] = [
    BigInt(envelope.strategyCommitment.hash),
    BigInt(`0x${envelope.matchId.replace(/-/g, '')}`),
    BigInt(envelope.turn),
    BigInt(envelope.state.selfBalance),
    BigInt(envelope.state.opponentBalance),
    BigInt(ACTION_CODES[action.type]),
    amount,
    1n, // circuitVersion "v1"
  ];
  return keccak256(concat(fields.map(word)));
}

export async function processStealTurn(
  envelope: StealTurnEnvelope,
): Promise<StealResponse> {
  const state: StealState = {
    selfBalance: envelope.state.selfBalance,
    opponentBalance: envelope.state.opponentBalance,
    selfFortifiedUntilTurn: envelope.state.selfFortifiedUntilTurn,
    opponentFortifiedUntilTurn: envelope.state.opponentFortifiedUntilTurn,
  };

  const action = decideAction(state);

  // Build the action object WITHOUT an amount key for HOLD/FORTIFY —
  // the platform schema rejects the field entirely for those actions.
  const actionObj: { type: string; amount?: number } = { type: action.type };
  if (action.type === 'EXTRACT') {
    // EXTRACT amount is capped at 10 by the game rules; clamp defensively.
    actionObj.amount = Math.min(10, Math.max(1, Math.trunc(action.amount)));
  }
  const effectiveAction: StealAction =
    action.type === 'EXTRACT'
      ? { type: 'EXTRACT', amount: actionObj.amount as number }
      : action;

  const publicInputsHash = computePublicInputsHash(envelope, effectiveAction);

  // Policy proof: proves we followed the committed strategy. Generation is
  // stubbed until circuit inputs + user strategy exist (src/proofs.ts).
  const generated = await generatePolicyProof({
    envelope: envelope as unknown as Record<string, unknown>,
    action: effectiveAction as unknown as Record<string, unknown>,
    publicInputsHash,
  });

  // Idempotency: the envelope nonce is unique per turn, so keying on it is
  // unique per turn AND stable if the platform retries the same envelope
  // (only the first submission per key is accepted). Fallback: random UUID.
  const idempotencyKey = envelope.nonce
    ? `${envelope.matchId}:${envelope.turn}:${envelope.nonce}`
    : `${envelope.matchId}:${envelope.turn}:${randomUUID()}`;

  return {
    matchId: envelope.matchId,
    turn: envelope.turn,
    action: actionObj,
    policyProof: {
      circuitVersion: 'v1',
      ...(generated
        ? { proof: generated.proof, public_signals: generated.publicSignals }
        : {}),
      publicInputsHash,
    },
    agentTimestamp: new Date().toISOString(),
    idempotencyKey,
  };
}
