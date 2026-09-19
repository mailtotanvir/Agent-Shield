# GCP r4 Evidence Summary

Date: 2026-09-19

Project: `redacted-gcp-project`

Region/zone: `northamerica-northeast1` / `northamerica-northeast1-a`

## Result

- The node, Calico daemon, and Calico Typha became ready.
- An application pod reached the Kubernetes API service.
- The broker and operator became available.
- The broker resolved to the intended
  `[redacted-broker-service-account]` identity.
- Workload Identity-backed KMS encryption completed and the encrypted envelope
  reported generation 1.
- The unauthorized workload received HTTP 403.
- The authorized workload reached the broker, where decryption raised
  `AttributeError` and was safely returned as HTTP 503.

The diagnostic identified a deterministic adapter defect rather than an IAM,
network, capacity, or KMS rejection. `DecryptResponse` has no
`verified_ciphertext_crc32c` or
`verified_additional_authenticated_data_crc32c` fields. KMS validates those
request checksums server-side and returns `plaintext_crc32c` for response
validation. AgentShield now uses that real response contract. The updated mock
matches the provider schema, preventing recurrence.

The fix passed all 46 tests with 73.34% branch coverage plus Ruff, strict mypy,
Bandit, Semgrep, and pip-audit on OCI. Because r4 authorized one attempt, the
corrected path was not redeployed without new approval.

## Cost

The fresh pre-run quote was `$0.1667` maximum against a `$0.25` cap. The full
lifecycle ran from `04:11:37Z` to `04:25:05Z`; GKE create through delete
completion covered 11.4 minutes and Cloud Build used 49.7 seconds. Applying the
captured paid-tier prices gives a conservative estimated gross r4 cost of
**$0.054 USD**. Actual billing remains pending.

Known estimated GCP experiment cost is now
`$0.061 + $0.152 + $0.060 + $0.054 = $0.327` before tax.

## Teardown

Read-only verification returned empty inventories for GKE clusters, Compute
Engine instances, disks, addresses, the r4 Artifact Registry repository,
dedicated service accounts, and the source bucket. The KMS key version is
destruction-scheduled. Container API disablement remains blocked only by stale
deleted-node-pool asset records and carries no usage charge by itself.
