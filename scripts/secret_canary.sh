#!/usr/bin/env bash
# Secret-scanner canary.
#
# Generates FRESH, random, never-committed fake Web3 secrets in a temp directory and asserts that
# Gitleaks (with this repo's .gitleaks.toml) detects every one of them. If a config edit, a regex
# typo or a tool upgrade silently breaks a rule, this fails loudly instead of the secret scan
# quietly passing.
#
# Usage: scripts/secret_canary.sh <gitleaks-image>
set -euo pipefail

image="${1:?usage: $0 <gitleaks-image>}"
python="${PYTHON:-python3}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

# Git Bash on Windows: hand Docker native paths and stop MSYS from rewriting container paths.
export MSYS_NO_PATHCONV=1
host_path() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi; }

rand_hex() { "$python" -c 'import secrets,sys; print(secrets.token_hex(int(sys.argv[1])))' "$1"; }
rand_upper_alnum() {
  "$python" -c 'import secrets,string,sys; a=string.ascii_uppercase+string.digits; print("".join(secrets.choice(a) for _ in range(int(sys.argv[1]))))' "$1"
}
rand_words() {
  "$python" -c 'import secrets,string,sys; print(" ".join("".join(secrets.choice(string.ascii_lowercase) for _ in range(6)) for _ in range(int(sys.argv[1]))))' "$1"
}

mkdir -p "$workdir/fixtures"
cat >"$workdir/fixtures/config.ts" <<EOF
export const config = {
  deployerPrivateKey: "0x$(rand_hex 32)",
  rpc: "https://mainnet.infura.io/v3/$(rand_hex 16)",
  alchemy: "https://eth-mainnet.g.alchemy.com/v2/$(rand_hex 16)",
  quicknode: "https://old-red-sea.ethereum-mainnet.quiknode.pro/$(rand_hex 20)/",
  etherscanApiKey: "$(rand_upper_alnum 34)",
  mnemonic: "$(rand_words 12)",
};
EOF
printf 'SIGNER=0x%s\n' "$(rand_hex 32)" >"$workdir/fixtures/.env.production"

docker run --rm \
  -v "$(host_path "$workdir/fixtures"):/scan:ro" \
  -v "$(host_path "$repo_root/.gitleaks.toml"):/config/.gitleaks.toml:ro" \
  -v "$(host_path "$workdir"):/out" \
  "$image" dir /scan --config /config/.gitleaks.toml --no-banner --redact \
  --report-format json --report-path /out/report.json --exit-code 0 >/dev/null

expected=(
  evm-private-key
  evm-private-key-in-env-file
  bip39-mnemonic
  infura-rpc-url
  alchemy-rpc-url
  quicknode-rpc-url
  block-explorer-api-key
)

detected="$("$python" -c 'import json,sys; print("\n".join(sorted({f["RuleID"] for f in json.load(open(sys.argv[1]))})))' "$(host_path "$workdir/report.json")")"

missing=0
for rule in "${expected[@]}"; do
  if grep -qx "$rule" <<<"$detected"; then
    echo "  [ok]      $rule"
  else
    echo "  [MISSING] $rule"
    missing=1
  fi
done

if [[ "$missing" -ne 0 ]]; then
  echo "::error title=Secret scanner canary failed::Gitleaks did not detect every planted Web3 secret. The secret scan cannot be trusted."
  exit 1
fi
echo "Secret scanner canary passed: all ${#expected[@]} Web3 rules detected freshly generated secrets."
