# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Report privately through GitHub's
[private vulnerability reporting](../../security/advisories/new) for this repository. Include:

- the affected component (contract, workflow, Terraform module or policy),
- reproduction steps or a proof-of-concept test,
- the impact you believe it has.

You can expect an acknowledgement within 72 hours and a status update within 7 days.

## Scope

| In scope | Out of scope |
| --- | --- |
| `contracts/src/**` | `contracts/canary/**` (intentionally vulnerable test fixture) |
| `.github/workflows/**` (CI/CD supply-chain issues) | Findings that require a compromised GitHub org owner |
| `infra/terraform/**`, `policies/**` | Third-party dependencies (report upstream) |

## Intentionally vulnerable code

`contracts/canary/VulnerableVault.sol` is deliberately exploitable. It is a control sample used to prove
that the scanners in the pipeline still detect known bugs. It is never deployed.
