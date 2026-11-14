# Circuit Input Mappings — zkVerify Agent Games (RECOVERED)

Recovered 2026-11-14 by dictionary attack against the official circuit WASM
artifacts, and validated end-to-end for Proof Gatekeeper with real
`snarkjs.groth16.fullProve` + local `groth16.verify` runs.

## Method (why this is proof, not guessing)

- circom_runtime (Circom 2.x) resolves input names by **FNV-1a 64-bit hash**
  (`fnvHash` in `circom_runtime/js/utils.js`, offset `0xCBF29CE484222325`,
  prime `0x100000001B3`). The WASM export `getInputSignalSize(hMSB, hLSB)`
  returns the signal's size for a real input name and `0` for anything else.
  A 64-bit hash match is collision-grade evidence.
- `getInputSize()` gives the total number of scalar inputs. For both circuits
  the dictionary-recovered names sum **exactly** to that total — no input is
  missing.
- Controls (Steal): removing `salt` from a complete input set fails with
  `Not all inputs have been set. Only 16 out of 17`.
- Nothing was published elsewhere: web/GitHub searches for
  `GatekeeperEvaluation` / `VfyPolicyProof` found no circom source, and
  `agentgames.zkverify.io/circuits/` serves only `.wasm` + `_final.zkey`
  (`gatekeeper.sym`, `gatekeeper.r1cs`, `vfy-policy.sym`,
  `verification_key.json` all return 404).

---

## 1. Proof Gatekeeper — FULLY SOLVED ✅

Artifacts: `circuits/gatekeeper.wasm`, `circuits/gatekeeper_final.zkey`
vkHash: `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`
Template: `GatekeeperEvaluation` · Circom 2.2.3 · witness size 647
**nPublic = 13** (verification key) · **total scalar inputs = 13**

### Inputs (all size 1)

| Signal | FNV-1a hash | Public? | Source / meaning |
|---|---|---|---|
| `registeredVkHash` | `14418c3ee75f7a4e` | public | envelope `input.registered_vk` |
| `proofVkHash` | `3b2514e2617cb386` | public | envelope `input.proof_vk` |
| `minimum` | `c92fe3ad0447b657` | public | envelope `input.minimum` |
| `publicBalance` | `9c9aac1639b93cc4` | public | envelope `input.public_balance` |
| `expiryBlock` | `9cef1f487868b4fb` | public | envelope `input.expiry_block` |
| `currentBlock` | `bab23a24475d685f` | public | envelope `input.current_block` |
| `recipient` | `3d0abea328337078` | public | envelope `input.recipient` |
| `conditionRecipient` | `acbdf1453659f53d` | public | envelope `input.condition_recipient` |
| `amount` | `8113fe7ea2b16969` | public | envelope `input.amount` |
| `maxTransfer` | `12eb7fd2c76a4dda` | public | envelope `input.max_transfer` |
| `decision` | `4065e278cd7560a3` | public | agent's decision: **1 = APPROVE, 0 = REJECT** |
| `taskId` | `0a29366601e1e7e1` | public | task identifier as a field element (see caveats) |
| `salt` | `097f5318bf97c581` | **private** | agent-chosen random field element |

Note: the envelope's `proof_tx` has **no** circuit input — it is not proven
inside the Gatekeeper circuit.

### Output & public-signal order (observed from real fullProve runs)

`publicSignals` (13) come back in this exact order:

```
[ output, registeredVkHash, proofVkHash, minimum, publicBalance,
  expiryBlock, currentBlock, recipient, conditionRecipient,
  amount, maxTransfer, decision, taskId ]
```

The single output is a hash that binds the proof to the task: in sensitivity
tests it **changed** when `salt` or `taskId` changed and was **invariant** to
`decision`, `proofVkHash`, `publicBalance`, `currentBlock`,
`conditionRecipient`, and `amount`. (Dependence on `registeredVkHash`,
`minimum`, `expiryBlock`, `recipient`, `maxTransfer` was not isolated — they
were constant across those runs. The circuit computes it; the agent never
needs its formula.)

### Decision semantics — enforced by the circuit (assert at GatekeeperEvaluation line 102)

- Genuine case (vk match, balance ≥ minimum, amount ≤ maxTransfer,
  recipient = conditionRecipient, currentBlock ≤ expiryBlock) with
  `decision = 1` → proof generates and **verifies locally = true**.
- Same genuine case with `decision = 0` → **Assert Failed**.
- Trap cases (recipient mismatch; or vk mismatch + insufficient balance +
  amount > max + expired) with `decision = 0` → proof generates, verifies.
- Trap case with `decision = 1` → **Assert Failed**.

So the circuit recomputes the evaluation itself; the agent's deterministic
checks in `src/gatekeeper.ts` must agree with it, and `decision` is fed in as
an input, not derived by the circuit for you.

### Verified example witness (genuine, decision = 1)

```json
{
  "registeredVkHash": 12345, "proofVkHash": 12345,
  "minimum": 1000, "publicBalance": 1460,
  "expiryBlock": 8430000, "currentBlock": 8420000,
  "recipient": 999, "conditionRecipient": 999,
  "amount": 500, "maxTransfer": 1000,
  "decision": 1, "taskId": 777, "salt": 42
}
```
→ publicSignals[0] = `11334721537671343503322080283377146843412703842105888593462577961181436591023`,
`groth16.verify(vk, publicSignals, proof) = true`.

### Caveats for implementation

- **Value encoding:** envelope fields arrive as hex/decimal strings; convert
  each to a field element (`BigInt(value)`; the witness calculator reduces
  mod the BN254 prime). Exact ground truth = the platform's practice tasks.
- **taskId conversion is the one unknown:** the envelope's `task_id` is a
  string like `gk_8d31_...`; how the platform maps it to the `taskId` field
  element is not documented. Confirm against a practice-task payload before
  scored rounds.
- **salt:** agent-generated, keep it secret and fresh per task.

---

## 2. Steal the VFY (vfy-policy) — NAMES FULLY RECOVERED, semantics pending

Artifacts: `circuits/vfy-policy.wasm`, `circuits/vfy-policy_final.zkey`
vkHash: `0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047`
Template: `VfyPolicyProof` · Circom 2.2.3 · witness size 1909
**nPublic = 9** (verification key) · **total scalar inputs = 17**

### Inputs

| Signal | FNV-1a hash | Size | Notes |
|---|---|---|---|
| `commitment` | `5df5731a340b4640` | 1 | envelope `strategyCommitment.hash` |
| `matchId` | `d2fc3582573022eb` | 1 | match UUID with hyphens stripped, as integer (per publicInputsHash spec) |
| `turnNumber` | `181dbad83f18ebc7` | 1 | envelope `turn` |
| `selfBalance` | `7b9a3cf7a1622435` | 1 | envelope `state.selfBalance` |
| `opponentBalance` | `d7801c66f43ff1b8` | 1 | envelope `state.opponentBalance` |
| `action` | `6568640b035a56df` | 1 | action code: HOLD 0 / FORTIFY 1 / EXTRACT 2 |
| `amount` | `8113fe7ea2b16969` | 1 | 0 for HOLD/FORTIFY |
| `circuitVersion` | `bd5d810f12f74388` | 1 | `1` for "v1" |
| `strategyParams` | `c07a189808b648c2` | **8** | the user's committed strategy parameters (private, inferred) |
| `salt` | `097f5318bf97c581` | 1 | commitment salt (private, inferred) |

Sum: 9×1 + 8 = **17 = getInputSize()** — complete, nothing missing.

These 8 scalar names are exactly the fields of the official
`publicInputsHash` formula (commitment, matchId, turn, selfBalance,
opponentBalance, action, amount, circuitVersion) — independent
cross-validation.

**Inferred split** (arithmetic, not yet proof-observed): the 8 publicInputsHash
fields are the public inputs, + 1 output = nPublic 9; `strategyParams[8]` +
`salt` (9 scalars) are private.

### What is still unknown for Steal

- Naive inputs pass the input stage but fail with
  `Assert Failed … VfyPolicyProof line: 72`. A passing proof additionally
  needs the **commitment derivation** (how `commitment` is computed from
  `strategyParams` + `salt` — a Poseidon preimage layout that is not
  published and was not recovered here) and the **policy semantics** (how the
  8 strategy params determine `action` for a given state). The params are the
  user's strategy by design; the commitment value is expected to be produced
  at dashboard commitment-registration time. Confirm both via the dashboard
  flow / practice turns before Swiss rounds.

---

## Verdict for `src/proofs.ts`

- `generateGatekeeperProof`: **implementable now, end-to-end validated.**
  Replace the `mapGatekeeperInputs() → null` stub with the mapping above
  (envelope → the 13 inputs, decision 1/0 from the deterministic checks,
  fresh random `salt`), then `snarkjs.groth16.fullProve`. Only the `taskId`
  string→field conversion needs practice-task confirmation.
- `generatePolicyProof` (Steal): the input mapping can be written now
  (names/sizes certain), but proofs will not pass until the user's
  `strategyParams` are set and the commitment derivation is confirmed.
