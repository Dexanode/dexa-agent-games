/**
 * Boundary audit — Gatekeeper circuit semantics vs our evaluateGatekeeper
 * rules. For each case we try to prove BOTH decisions with the real
 * circuit; exactly one should succeed, and it must match the decision our
 * rules produce. Run: node tools/audit-boundaries.mjs (after npm run build).
 */
import { generateGatekeeperProof } from '../dist/src/proofs.js';

const VK = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const VK_OTHER = '0x1111111111111111111111111111111111111111111111111111111111111111';
const RECIPIENT = '0x1234567890abcdef1234567890abcdef12345678';
const RECIPIENT_OTHER = '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';

function env(overrides = {}) {
  return {
    task_id: 'gk_8d31_ab12',
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
      ...overrides,
    },
  };
}

// [name, overrides, decision our current rules produce]
const CASES = [
  ['base genuine', {}, 'APPROVE'],
  ['amount == max_transfer', { amount: '1000' }, 'APPROVE'],
  ['amount == max+1', { amount: '1001' }, 'REJECT'],
  ['balance == minimum', { public_balance: '1000' }, 'APPROVE'],
  ['balance == minimum-1', { public_balance: '999' }, 'REJECT'],
  ['current == expiry', { current_block: 8430000 }, 'REJECT'], // strict <: fixed 2026-11-15 (first audit run caught our `>` check approving here)
  ['current == expiry+1', { current_block: 8430001 }, 'REJECT'],
  ['amount == 0', { amount: '0' }, 'APPROVE'],
  ['minimum == 0, balance == 0', { minimum: '0', public_balance: '0' }, 'APPROVE'],
  ['recipient mismatch', { recipient: RECIPIENT_OTHER }, 'REJECT'],
  ['vk mismatch', { proof_vk: VK_OTHER }, 'REJECT'],
];

let mismatches = 0;
for (const [name, overrides, ours] of CASES) {
  const a = await generateGatekeeperProof(env(overrides), 'APPROVE');
  const r = await generateGatekeeperProof(env(overrides), 'REJECT');
  const circuit = a && !r ? 'APPROVE' : r && !a ? 'REJECT' : a && r ? 'BOTH' : 'NEITHER';
  const match = circuit === ours;
  if (!match) mismatches++;
  console.log(
    `AUDIT ${match ? 'MATCH   ' : 'MISMATCH'} ${name}: circuit=${circuit} ours=${ours}`,
  );
}
console.log(`AUDIT DONE mismatches=${mismatches}`);
process.exit(mismatches === 0 ? 0 : 1);
