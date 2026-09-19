# GCP r6 Evidence Summary

Date: 2026-09-19

Project: `redacted-gcp-project`

Region/zone: `northamerica-northeast1` / `northamerica-northeast1-a`

## Result

R6 completed the core GKE and Cloud KMS evidence path:

- three consecutive node, Calico daemon, and Typha readiness observations held;
- an in-cluster pod reached the Kubernetes API successfully;
- the broker received its expected Google service-account identity through GKE
  Workload Identity;
- ingestion produced encrypted generation 1 using the configured Cloud KMS key;
- the authorized agent sidecar retrieved and wrote plaintext into its
  memory-backed `emptyDir`, and the verifier matched its SHA-256 digest; and
- a different ServiceAccount and pod label were denied with HTTP 403.

The broker was configured only for the GCP KMS provider. Its successful 200
responses and the verifier's match against the independently recorded ingest
digest demonstrate that the corrected KMS unwrap path worked. Cloud Audit Logs
contained key administration records but not Data Access encrypt/decrypt events,
so no claim of per-operation audit correlation is made.

The application checks succeeded, but the lifecycle process exited nonzero
afterward: its final grep expected the obsolete phrase `secret delivery
verified`, while the verifier emitted `verified generation delivery`. That
post-check was corrected in the archived runner without rerunning GCP.

## Cost

The fresh pre-run quote was `$0.1667` maximum against a `$0.25` cap. Cloud Build
used 46.5 seconds. The cluster create operation began at `05:24:11Z` and cluster
deletion completed at `05:34:11Z`, a 10.0-minute billable cluster window. KMS
destruction was requested at `05:34:42Z`. Applying the captured paid-tier
prices gives a conservative estimated gross r6 cost of **$0.047 USD**. Actual
billing remains pending.

Known estimated GCP experiment cost is now
`$0.061 + $0.152 + $0.060 + $0.054 + $0.049 + $0.047 = $0.423` before tax.

## Teardown

Read-only verification returned empty inventories for GKE clusters, Compute
Engine instances, disks, addresses, the r6 Artifact Registry repository,
dedicated service accounts, and the source bucket. The KMS version is
destruction-scheduled. Container API disablement remains blocked by stale
deleted-node-pool asset records and carries no usage charge by itself.

Broader Stage 3D scenarios such as removing a live binding, pod recreation, key
version failure, and Data Access audit correlation remain future hardening work;
they are not required to establish this core demonstration.
