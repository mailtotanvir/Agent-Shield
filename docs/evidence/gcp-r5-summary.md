# GCP r5 Evidence Summary

Date: 2026-09-19

Project: `redacted-gcp-project`

Region/zone: `northamerica-northeast1` / `northamerica-northeast1-a`

## Result

R5 was intended to validate the corrected Cloud KMS decrypt adapter. The GKE
cluster, node, Calico daemon, and Typha deployment initially reported Ready.
Before AgentShield was installed, the mandatory pod-to-Kubernetes-API probe
exited with code 1. During the same interval GKE replaced its initial Calico
node and Typha pods. The runner stopped rather than bypassing its network gate.

The probe log was not captured, so this evidence does not attribute the exit to
a specific Python exception. R5 never exercised ingestion or decryption and
therefore neither confirms nor contradicts the corrected KMS code. A future
runner should require a short stable-readiness interval, retry the connectivity
request, fail immediately on a terminal pod phase, and retain the probe log.

## Cost

The fresh pre-run quote was `$0.1667` maximum against a `$0.25` cap. The full
lifecycle ran from `04:32:59Z` to `04:45:24Z`; GKE create through delete
completion covered 10.2 minutes and Cloud Build used 50.1 seconds. Applying the
captured paid-tier prices gives a conservative estimated gross r5 cost of
**$0.049 USD**. Actual billing remains pending.

Known estimated GCP experiment cost is now
`$0.061 + $0.152 + $0.060 + $0.054 + $0.049 = $0.376` before tax.

## Teardown

Read-only verification returned empty inventories for GKE clusters, Compute
Engine instances, disks, addresses, the r5 Artifact Registry repository,
dedicated service accounts, and the source bucket. The KMS version is
destruction-scheduled. Container API disablement remains blocked by stale
deleted-node-pool asset records and carries no usage charge by itself.
