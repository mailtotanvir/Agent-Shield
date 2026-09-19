# OCI Temporal Redesign Validation

Observed: 2026-09-19T02:06:22Z

- Environment: existing OCI ARM64 instance, isolated directory under `/tmp`.
- Incremental infrastructure cost: **$0.00 USD**. The standing OCI instance cost
  remains outside this experiment and is not claimed as free.
- GCP resources created or changed: none.
- Dependency lock SHA-256:
  `62055bb009a26c6af48d8c8f24d35714f6bc3dda7941d5ad9487d2b58c3bf6a3`.
- Ruff: pass.
- Strict mypy: pass across 37 source files.
- pytest: 45 passed, including Temporal retry, compensation, and plaintext
  history-exclusion cases.
- Branch coverage: 73.12% (required minimum: 70%).
- Bandit: no findings.
- Semgrep: no findings across 37 Python targets.
- pip-audit: no known vulnerabilities; the unpublished local `agentshield`
  package is correctly reported as unavailable from PyPI.
- Teardown script: Bash syntax valid and missing-confirmation guard exits with
  status 2 before invoking `gcloud`.

The Temporal test server and Python environment were temporary test resources on
the existing OCI instance. No production Temporal service was provisioned.
