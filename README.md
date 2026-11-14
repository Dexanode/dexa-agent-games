# dexa-agent-games

0xDexa's agent endpoint for the **zkVerify Agent Games** — the two automated
tracks, **Proof Gatekeeper** and **Steal the VFY** (400,000 VFY total prize
pool, 100,000 VFY per track; competition closes **21 Nov 2026**).

The agent is a single signed HTTP endpoint: the platform POSTs a task/turn
envelope, the agent decides deterministically, and answers with a signed
JSON response in under 60 seconds. AI/LLMs are **not** used in any final
decision — all logic is plain deterministic code.

## Endpoints

| Route | Method | Purpose |
| --- | --- | --- |
| `/api/agent` (Vercel) or `/agent` (local) | POST | Agent Games endpoint (HMAC-signed in & out) |
| `/api/health` (Vercel) or `/health` (local) | GET | Unsigned health check → `{"ok":true,"service":"dexa-agent-games"}` |

Message types handled on the agent endpoint:

- `{"type":"agent-games.preflight.v1", ...}` → `{"ok":true,"protocolVersion":"v1"}`
- `{"type":"agent-games.proof-gatekeeper.v1", ...}` → `{"decision":"APPROVE"|"REJECT","reason_code":"...","proof_tx":"...","proof":...,"public_signals":[...]}`
- Steal the VFY turn envelope (`eventId:"steal-the-vfy"`) → `{matchId, turn, action, policyProof, agentTimestamp, idempotencyKey}`

Security model (from the official Build guide):

- Inbound HMAC verified over the **raw** request body *before* JSON parsing;
  mismatch → 401. Header: `x-agent-games-signature`.
- Every response is signed the same way over the raw response body.
- Fail closed everywhere: bad signature, unknown type, stale/expired task,
  replayed proof, missing config → rejection/error, never an approval.
- Deadline discipline: internal work (incl. Kurier polling) is bounded well
  under the 60 s hard limit.

## Local run

```bash
npm install
npm run download-circuits   # fetch wasm+zkey artifacts into circuits/ (gitignored)
cp .env.example .env         # fill in AGENT_GAMES_HMAC_SECRET at minimum
npm test                     # builds + boots the server + runs the HTTP harness
npm start                    # node dist/server.js (PORT, default 8787)
curl localhost:8787/health
```

## Environment variables

| Var | Required | Notes |
| --- | --- | --- |
| `AGENT_GAMES_HMAC_SECRET` | **yes** | Platform-generated. Dashboard → agent → **Rotate Secret**. Never commit it. Without it, POSTs are refused (503) by design. |
| `AGENT_GAMES_HMAC_ALG` | no | `sha256` (default) or `sha512`. **Assumption:** the Build guide does not state the algorithm; SHA-256 hex is our default. |
| `KURIER_API_KEY` | for proof submission | Kurier mainnet API key. Without it, decisions still work; proofs are generated but not submitted to zkVerify. |
| `PORT` | no | Local server only. |

## Layout

```
api/agent.ts        Vercel adapter (raw body, bodyParser off)
api/health.ts       Vercel health adapter
server.ts           local node:http server (same handler)
src/handler.ts      routing, signature gate, fail-closed errors
src/hmac.ts         HMAC sign/verify (timing-safe)
src/gatekeeper.ts   Proof Gatekeeper checks (7 rules, in spec order)
src/steal.ts        Steal the VFY turn handling + publicInputsHash (keccak256, viem)
src/strategy.ts     ⚠ USER-OWNED strategy params — intentionally EMPTY (see below)
src/proofs.ts       snarkjs Groth16 proof generation (circuit inputs mapped — see FINDINGS.md)
src/kurier.ts       Kurier submit + poll until Finalized (≤45 s)
circuits/           Groth16/BN128 artifacts (gitignored, re-fetch via script)
test/harness.mjs    signed end-to-end harness (27 checks)
```

## Circuits

| Event | Circuit | vkHash | Public signals |
| --- | --- | --- | --- |
| Proof Gatekeeper | `GatekeeperEvaluation` | `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0` | 13 |
| Steal the VFY | `VfyPolicyProof` | `0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047` | 9 |

Input-signal names for both circuits were recovered by probing the WASM
witness calculators and the mappings are implemented in `src/proofs.ts` —
see **FINDINGS.md** for exactly what was verified, what is still assumed
(encodings, `decision`/`salt` semantics), and what remains stubbed.

## Deploy to Vercel (sketch)

1. Push this repo to GitHub as **Dexanode/dexa-agent-games** (public —
   the registration form requires a public repo URL).
2. Import into Vercel (framework preset: *Other*; no build command needed —
   the `api/` functions are self-contained TypeScript; root `tsconfig.json`
   is picked up automatically).
3. Set env vars in Vercel: `AGENT_GAMES_HMAC_SECRET`, `KURIER_API_KEY`.
4. Note the production URL, e.g. `https://dexa-agent-games.vercel.app/api/agent`.

> ⚠ Circuit artifacts (wasm/zkey, ~5.9 MB total) are gitignored. If proof
> generation must run on Vercel, the artifacts must be made available to the
> function (bundle them / fetch at cold start) — currently an open TODO;
> see FINDINGS.md. The decision path works without them (proof omitted).

## Registration steps (dashboard, by the user)

1. Sign in at agentgames.zkverify.io (X or wallet) and complete the profile
   (handle, country, bio; wallet address needed later to claim prizes).
2. Deploy first, then **Register agent**: name, public repo URL
   (`https://github.com/Dexanode/dexa-agent-games`), endpoint URL
   (`https://<deployment>/api/agent`).
3. Click **Rotate Secret**, copy the HMAC secret into the deployment env
   (never into chat/git), redeploy.
4. Run the dashboard **preflight** test — it must return
   `{"ok":true,"protocolVersion":"v1"}` with a valid signature.
5. Enter events; live arena runs 17:30–03:30 WIB nightly. Gatekeeper rounds
   run 13–20 Nov; Steal the VFY Swiss rounds 13–17 Nov, knockouts 18–20 Nov,
   final 21 Nov. **Steal the VFY additionally requires committing a strategy
   before playing** — and the strategy is the user's own (below).

## ⚠ Strategy is user-owned

The official guide forbids letting an AI invent the Steal the VFY strategy.
`src/strategy.ts` therefore ships with `STRATEGY_PARAMS = null` and plays
**HOLD** (no spend, no risk, no amount field) until the user defines his own
parameters — the circuit takes them as `strategyParams[8]` plus a `salt`,
committed via `strategyCommitment.hash`.

## Open TODOs

- [ ] HMAC algorithm assumption (SHA-256 hex) — confirm via dashboard preflight.
- [ ] `decision` encoding (1 = APPROVE) and `salt` semantics in the
      Gatekeeper circuit — assumptions documented in FINDINGS.md.
- [ ] Strategy params (user) + how `strategyCommitment.hash` is computed
      from `strategyParams` + `salt` (Poseidon arrangement TBD).
- [ ] Kurier API key + HMAC secret from the user (secure channel only).
- [ ] Circuit artifacts availability on Vercel for in-function proving.
- [ ] Deploy + registration (user-approved steps).
