#!/usr/bin/env bash
# Re-fetch the Groth16/BN128 circuit artifacts (wasm + proving key) for both
# automated events from the official Agent Games site.
# Artifacts are gitignored; run this after cloning.
set -euo pipefail
cd "$(dirname "$0")/../circuits"
BASE="https://agentgames.zkverify.io/circuits"
for f in gatekeeper.wasm gatekeeper_final.zkey vfy-policy.wasm vfy-policy_final.zkey; do
  echo "downloading $f"
  curl -sSL -o "$f" "$BASE/$f"
done
ls -la
