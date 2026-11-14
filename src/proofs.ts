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
 * TODO(circuit-input-mapping): the .wasm artifacts do NOT contain plaintext
 * input-signal names — circom 2.x hashes signal names inside the witness
 * calculator, and no .sym/.r1cs files are published on the Agent Games site.
 * From `strings` on the wasm we only recover the top-level template names
 * ("GatekeeperEvaluation" and "VfyPolicyProof") and that both circuits use
 * Poseidon hashing plus LessThan/GreaterThan/IsEqual comparisons. That is
 * NOT enough to map task-envelope fields to circuit inputs confidently, so
 * the mappers below intentionally return null (proof omitted) until the
 * official input names are known (starter prompt / Playbook / Discord).
 * See FINDINGS.md for the full inspection notes.
 *
 * When the mapping is known: fill in mapGatekeeperInputs()/mapPolicyInputs()
 * with the exact signal names and the functions below will call
 * snarkjs.groth16.fullProve for real.
 */
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const GATEKEEPER_VK_HASH =
  '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
export const VFY_POLICY_VK_HASH =
  '0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047';

export interface GeneratedProof {
  proof: unknown;
  publicSignals: string[];
}

function circuitsDir(): string {
  if (process.env.CIRCUITS_DIR) return process.env.CIRCUITS_DIR;
  // dist/proofs.js -> ../circuits ; src (tsx) -> ../circuits. Both resolve to
  // <project>/circuits relative to this file's parent directory.
  const here = path.dirname(fileURLToPath(import.meta.url));
  return path.resolve(here, '..', 'circuits');
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
 * TODO: map Proof Gatekeeper task-envelope `input` fields to the
 * GatekeeperEvaluation circuit's input signals. Returns null while the
 * mapping is unknown — DO NOT guess signal names; a wrong mapping makes
 * fullProve throw or, worse, produces proofs over the wrong statement.
 */
export function mapGatekeeperInputs(
  _taskInput: Record<string, unknown>,
): Record<string, unknown> | null {
  // TODO(circuit-input-mapping): fill in once official signal names known.
  return null;
}

export async function generateGatekeeperProof(
  taskInput: Record<string, unknown>,
): Promise<GeneratedProof | null> {
  const inputs = mapGatekeeperInputs(taskInput);
  if (!inputs) {
    console.warn(
      '[proofs] gatekeeper circuit input mapping unknown — returning no proof (TODO)',
    );
    return null;
  }
  try {
    return await fullProve(
      inputs,
      'gatekeeper.wasm',
      'gatekeeper_final.zkey',
    );
  } catch (err) {
    console.error('[proofs] gatekeeper fullProve failed:', (err as Error).message);
    return null;
  }
}

/**
 * TODO: map Steal the VFY policy inputs. The vfyPolicy circuit proves the
 * agent followed its committed strategy; its inputs necessarily include
 * private strategy material owned by the USER (see src/strategy.ts), so this
 * cannot be completed until both the signal names AND the user's strategy
 * parameters exist.
 */
export function mapPolicyInputs(
  _args: Record<string, unknown>,
): Record<string, unknown> | null {
  // TODO(circuit-input-mapping + user-strategy): fill in later.
  return null;
}

export async function generatePolicyProof(
  args: Record<string, unknown>,
): Promise<GeneratedProof | null> {
  const inputs = mapPolicyInputs(args);
  if (!inputs) {
    console.warn(
      '[proofs] vfy-policy circuit input mapping unknown — returning no proof (TODO)',
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
