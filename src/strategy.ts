/**
 * Steal the VFY — strategy.
 *
 * ⚠️ USER-OWNED. The official Agent Games build guide explicitly forbids
 * letting an AI invent the Steal the VFY strategy ("a vibecoded strategy
 * isn't a strategy"). Therefore:
 *
 *   - STRATEGY_PARAMS is intentionally EMPTY / unset.
 *   - decideAction() returns HOLD (the neutral, no-amount action) whenever
 *     params are unset, and contains NO heuristic of any kind.
 *
 * The user (0xDexa) must define the strategy parameters himself, commit to
 * them (the strategy commitment hash is part of the arena protocol), and
 * only then should decideAction() be implemented against those params.
 */

export interface StealState {
  selfBalance: string;
  opponentBalance: string;
  selfFortifiedUntilTurn: number | null;
  opponentFortifiedUntilTurn: number | null;
}

export type StealAction =
  | { type: 'HOLD' }
  | { type: 'FORTIFY' }
  | { type: 'EXTRACT'; amount: number };

/**
 * TODO(user): define YOUR strategy parameters here — e.g. thresholds,
 * extract sizing rules, fortify triggers. Shape is deliberately unspecified
 * until the user decides; keep it a plain data object so it can be hashed
 * into the strategy commitment exactly as played.
 */
export interface StrategyParams {
  // TODO(user): intentionally empty.
  [key: string]: unknown;
}

/** TODO(user): null until the user sets his own strategy. */
export const STRATEGY_PARAMS: StrategyParams | null = null;

export function decideAction(
  _state: StealState,
  params: StrategyParams | null = STRATEGY_PARAMS,
): StealAction {
  if (!params) {
    // No user strategy configured — HOLD is the only defensible default:
    // it spends nothing, risks nothing, and carries no amount field.
    return { type: 'HOLD' };
  }
  // TODO(user): implement decision logic strictly from `params`.
  // No heuristic is provided on purpose (see file header).
  return { type: 'HOLD' };
}
