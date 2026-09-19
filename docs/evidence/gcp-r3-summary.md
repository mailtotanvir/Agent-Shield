# GCP r3 Evidence Summary

Date: 2026-09-19

Project: `redacted-gcp-project`

Region/zone: `northamerica-northeast1` / `northamerica-northeast1-a`

## Result

The infrastructure workaround succeeded on one `e2-standard-4` node:

- node, Calico daemon, and Calico Typha readiness checks passed;
- an application pod reached the in-cluster Kubernetes API;
- broker and operator deployments became available;
- the operator reconciled the `AgentSecret` without RBAC warnings;
- Workload Identity-backed KMS encryption completed;
- the stored envelope reported generation 1 and retained only ciphertext;
- the unauthorized workload received HTTP 403.

The authorized request reached the broker but returned HTTP 503 because the
Cloud KMS decrypt operation failed. The implementation intentionally collapsed
the provider exception into a generic `EnvelopeError`, so retained logs cannot
distinguish IAM denial, provider rejection, or transport failure. This is not
recorded as a complete end-to-end success.

The post-run fix retains bounded provider status classification without logging
request data, ciphertext, tokens, or plaintext. A future rerun can therefore
identify the exact KMS failure safely.

## Cost

The pre-run official price quote was `$0.2520` maximum against a `$0.35` cap.
The complete lifecycle ran from `03:42:26Z` to `03:57:15Z`; GKE create through
delete completion covered approximately 12.9 minutes, and Cloud Build used
44.7 seconds. Applying the captured paid-tier list prices produces a
conservative estimated gross r3 cost of **$0.060 USD**. Actual billing remains
pending.

Known estimated GCP experiment cost is now `$0.061 + $0.152 + $0.060 = $0.273`
before tax.

## Teardown

Read-only verification returned empty inventories for GKE clusters, Compute
Engine instances, disks, addresses, the r3 Artifact Registry repository,
dedicated service accounts, and the dedicated source bucket. The KMS version
is destruction-scheduled. Container API disablement remains blocked by stale
deleted-node-pool asset records; an enabled API with no backing resources has
no usage charge.
