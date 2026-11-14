/**
 * Kurier client — submits Groth16 proofs to zkVerify mainnet and polls the
 * job until it reaches "Finalized".
 *
 * Endpoint shapes (submit endpoint is from the official starter spec):
 *   POST https://api.kurier.xyz/api/v1/submit-proof/{API_KEY}
 *   GET  https://api.kurier.xyz/api/v1/job-status/{API_KEY}/{JOB_ID}
 * ASSUMPTION: the job-status path/method follows Kurier's documented API
 * layout; the starter spec only pins the submit URL and the status names
 * (Submitted -> IncludedInBlock -> Finalized). Response JSON is parsed
 * defensively (jobId / status may be nested under `data`).
 *
 * The API key is interpolated into request URLs only — it is NEVER logged.
 */

export interface KurierSubmitParams {
  proof: unknown;
  publicSignals: string[];
  /** Verification-key hash registered on zkVerify (e.g. gatekeeper vkHash). */
  vk: string;
  apiKey: string;
  /** Hard bound for the whole submit+poll cycle. Keep well under the
   *  platform's 60s response deadline. Default 45s. */
  timeoutMs?: number;
  pollIntervalMs?: number;
}

export interface KurierResult {
  jobId: string;
  status: string;
  finalized: boolean;
}

const KURIER_BASE = 'https://api.kurier.xyz/api/v1';
const FINAL_STATUS = 'Finalized';

function extractJobId(json: any): string | null {
  return (
    json?.jobId ?? json?.data?.jobId ?? json?.id ?? json?.data?.id ?? null
  );
}

function extractStatus(json: any): string | null {
  return (
    json?.status ??
    json?.data?.status ??
    json?.metaStatus ??
    json?.data?.metaStatus ??
    null
  );
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * Submit a proof and poll until Finalized or timeout.
 * Returns null on transport/HTTP failure (caller decides — fail closed is
 * handled by the decision layer, not here).
 */
export async function submitProofAndWaitFinalized(
  params: KurierSubmitParams,
): Promise<KurierResult | null> {
  const timeoutMs = params.timeoutMs ?? 45_000;
  const pollIntervalMs = params.pollIntervalMs ?? 3_000;
  const deadline = Date.now() + timeoutMs;

  const body = {
    proofType: 'groth16',
    vkRegistered: true,
    proofOptions: { library: 'snarkjs', curve: 'bn128' },
    proofData: {
      proof: params.proof,
      publicSignals: params.publicSignals,
      vk: params.vk,
    },
  };

  let jobId: string | null = null;
  try {
    const res = await fetch(`${KURIER_BASE}/submit-proof/${params.apiKey}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(Math.max(1, deadline - Date.now())),
    });
    if (!res.ok) {
      console.error(`[kurier] submit failed: HTTP ${res.status}`);
      return null;
    }
    const json: any = await res.json();
    jobId = extractJobId(json);
    const status = extractStatus(json);
    if (!jobId) {
      console.error('[kurier] submit response had no job id');
      return null;
    }
    console.log(`[kurier] submitted job ${jobId} (status: ${status ?? '?'})`);
    if (status === FINAL_STATUS) {
      return { jobId, status, finalized: true };
    }
  } catch (err) {
    console.error('[kurier] submit error:', (err as Error).message);
    return null;
  }

  while (Date.now() < deadline) {
    await sleep(Math.min(pollIntervalMs, Math.max(0, deadline - Date.now())));
    try {
      const res = await fetch(
        `${KURIER_BASE}/job-status/${params.apiKey}/${jobId}`,
        { signal: AbortSignal.timeout(Math.max(1, deadline - Date.now())) },
      );
      if (!res.ok) {
        console.error(`[kurier] job-status failed: HTTP ${res.status}`);
        continue;
      }
      const json: any = await res.json();
      const status = extractStatus(json);
      console.log(`[kurier] job ${jobId} status: ${status ?? '?'}`);
      if (status === FINAL_STATUS) {
        return { jobId: jobId as string, status, finalized: true };
      }
    } catch (err) {
      console.error('[kurier] job-status error:', (err as Error).message);
    }
  }

  console.error(`[kurier] job ${jobId} not finalized within ${timeoutMs}ms`);
  return { jobId: jobId as string, status: 'Timeout', finalized: false };
}
