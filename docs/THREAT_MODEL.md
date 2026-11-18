# Threat model

Scope: the `SecureVault` contract, the CI/CD pipeline that tests and deploys it, and the AWS
infrastructure that holds the deployer's signing authority.

## Assets

| Asset | Why it matters |
| --- | --- |
| User funds held by `SecureVault` | Direct financial loss |
| Deployer / admin signing key | Controls contract deployment and, through roles, the protocol |
| Authenticated RPC endpoint (API key) | Abuse, billing fraud, request tampering via a malicious endpoint |
| CI/CD pipeline and its credentials | A compromised pipeline can ship malicious bytecode with a trusted key |
| Security-gate integrity | A silently broken scanner turns "green" into a false assurance |

## Threats and controls

| # | Threat | Control | Enforced by |
| --- | --- | --- | --- |
| T1 | Reentrancy drains the vault | `nonReentrant` + checks-effects-interactions | Slither, Mythril, `test_RevertWhen_TokenHookReentersWithdraw` |
| T2 | Accounting bug lets users withdraw more than deposited | Solvency / conservation invariants | 4 Foundry invariants, 256 runs x 128 calls in CI |
| T3 | Fee-on-transfer token inflates balances | Balance-delta accounting | Fuzz test against a 1%-fee token |
| T4 | Compromised account or undiscovered bug empties the vault at once | Rolling outflow rate limit (circuit breaker) | `invariant_OutflowWithinRateLimit` |
| T5 | Compromised guardian griefs the protocol | Pausers can pause but only admin can unpause | `test_RevertWhen_PauserTriesToUnpause` |
| T6 | Admin rescue function used as a backdoor | Rescue limited to surplus above `totalDeposits` | `testFuzz_RescueCanOnlyTakeSurplus` |
| T7 | Private key leaked from a laptop, `.env` or CI secret | Key generated and kept inside KMS (non-exportable) | `kms.tf`, Conftest `terraform.kms` |
| T8 | Private key / mnemonic / RPC key committed to git | Secret scanning of full history on every push + pre-commit hook | TruffleHog, Gitleaks (Web3 rules), secret canary |
| T9 | Fork PR or feature branch assumes the deploy role | OIDC trust pinned with `StringEquals` to `repo:<owner>/<repo>:environment:<env>` | Conftest `terraform.github_oidc` |
| T10 | Deploy role misused to sign arbitrary payloads | `kms:Sign` limited to ECDSA_SHA_256 over digests, on one key ARN | IAM + key policy conditions, Conftest |
| T11 | Key admin silently signs, or deletes the key | Separation of duties: admins have no `kms:Sign`; 30-day deletion window; `prevent_destroy`; alerts on `Sign`, `DisableKey`, `ScheduleKeyDeletion`, `PutKeyPolicy` | Conftest, `monitoring.tf` |
| T12 | Secret values leak through Terraform state | Secrets created empty, values set out-of-band; policy forbids `secret_string` | Conftest `terraform.secrets` |
| T13 | Malicious or hijacked GitHub Action / image / package | Actions pinned to commit SHAs, images pinned by digest, pip hash-locked, provider lockfile, 7-day Dependabot cooldown | zizmor, `requirements/slither.txt`, `.terraform.lock.hcl` |
| T14 | Script injection or token theft inside the workflow | Default-deny `permissions`, `persist-credentials: false`, no untrusted `${{ }}` in scripts | zizmor, actionlint |
| T15 | Scanner silently stops detecting (bad upgrade, broken config) | Scanner canaries: known-bad inputs must be flagged on every run | Slither, Mythril and Gitleaks canary steps |
| T16 | Deploying a commit that never passed the gates | Deploy workflow checks for a successful Security Pipeline run on the exact SHA, from `main`, behind a protected environment | `deploy.yml` |

## Accepted risks

| Risk | Rationale | Compensating control |
| --- | --- | --- |
| Deployer KMS key is not auto-rotated (Checkov `CKV_AWS_7`) | AWS cannot rotate asymmetric keys, and rotation would change the on-chain address | Rotation = provision a new key, transfer roles on-chain, then schedule old-key deletion |
| RPC secret is not auto-rotated (Checkov `CKV2_AWS_57`) | Third-party RPC providers expose no rotation API for a Lambda to call | Quarterly manual rotation (runbook below) + provider-side allowlists and rate limits |
| Rate-limit window resets on a fixed boundary | Up to 2x the limit can leave around a boundary; simpler and cheaper than a sliding window | Pause + monitoring; the cap still bounds the worst case |
| Pause also blocks withdrawals | During an active exploit, freezing outflows protects remaining funds | Only the admin (timelock/multisig) can unpause |
| `harden-runner` in audit mode | Block mode needs a curated allowlist of egress endpoints | Review the egress report and move to `block` once it is stable |

## Runbooks

### Rotate the RPC API key

1. Create a new key in the RPC provider dashboard and restrict it (allowed origins/IPs, method allowlist).
2. `aws secretsmanager put-secret-value --secret-id <rpc_url_secret_arn> --secret-string "<new url>"`
3. Run the deploy workflow in simulation mode to confirm connectivity.
4. Revoke the old key in the provider dashboard.

### Respond to a deployer-key alert

1. If the `Sign` event does not match an approved deploy run, disable the key immediately:
   `aws kms disable-key --key-id <deployer_key_arn>`.
2. Pause affected contracts from the guardian multisig.
3. Review CloudTrail for the calling role session (`gha-deploy-<run_id>`) and match it against the
   GitHub Actions run log.
