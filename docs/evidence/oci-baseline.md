# OCI Validation Evidence

Date: 2026-09-18  
GCP project reserved for later validation: `redacted-gcp-project`  
GCP resources created: none  
Incremental OCI resources created: none  
Recorded incremental cloud cost: **$0.00**

## Environment

- Existing user-managed OCI instance; its standing subscription cost is outside
  this experiment and is not represented as free.
- Ubuntu 24.04, Linux 6.17, ARM64, 4 vCPUs, 23 GiB RAM.
- 117 GiB disk free before validation.
- Docker 29.4.3.
- Temporary, checksum-verified tools under `/tmp/agentshield-validation`:
  uv 0.11.17, kubectl 1.37.0, kind 0.33.0, and Helm 4.3.0.
- Kubernetes node: kindest/node v1.37.0.

No packages or Kubernetes distribution were installed system-wide. The source,
virtual environment, binaries, evidence staging, and cluster were isolated under
`/tmp/agentshield-validation` or Docker.

## Verified results

- Ruff: pass.
- strict mypy: pass across 35 source files.
- pytest: 43 passing on CPython 3.12.3.
- branch coverage: 72.31%, above the 70% decision-path baseline.
- Bandit: no findings.
- custom Semgrep policy: 0 findings across 35 Python targets.
- pip-audit: no known vulnerabilities in locked third-party dependencies.
- Helm lint: pass.
- OCI ARM64 image: `sha256:9f1a11fd875d7beb5159974044443a9957641b581fb00c27015496fb2e9b7bd7`,
  67,866,969 bytes.
- Kubernetes end-to-end: broker and operator rolled out; an allowed pod received
  the expected secret generation and SHA-256; an unlisted ServiceAccount received
  HTTP 403.
- Cleanup: `kind get clusters` returned `No kind clusters found`; no
  `agentshield-evidence` container remained.

The Kubernetes test used a generated canary. Retained output contains only its
SHA-256, not the plaintext. This proves generic single-node Kubernetes behavior;
it does not prove GKE Workload Identity, Cloud KMS, availability, or production
resilience.

Raw sanitized logs and their checksums are listed in `run-manifest.json`.
