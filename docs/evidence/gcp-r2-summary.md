# GCP r2 Evidence Summary

Date: 2026-09-19
Project: `redacted-gcp-project`
Region/zone: `northamerica-northeast1` / `northamerica-northeast1-a`

## Demonstrated

- Four Cloud Build executions completed successfully and produced pinned images.
- A one-node zonal GKE Standard cluster was repeatedly created and deleted by the
  guarded lifecycle runner while diagnosing setup and propagation failures.
- The broker and operator deployments rolled out successfully.
- The corrected `scopedTo.matchLabels` CRD shape was accepted.
- One attempt completed Workload Identity-backed Cloud KMS encryption and wrote
  only the encrypted envelope to Kubernetes.
- The unauthorized ServiceAccount path returned HTTP 403.
- The lifecycle script captured diagnostics and automatically invoked teardown
  after every failure.

## Incomplete result and cause

The full authorized-delivery assertion did not complete. On the smallest
approved `e2-medium` node, GKE's Calico/Typha components were intermittently
unready or unschedulable because of CPU pressure. In the final attempt, both
ingest pods timed out connecting to the Kubernetes API service address. In an
earlier attempt, ingestion succeeded but the authorized broker request returned
a sanitized HTTP 503 while the same network components were unhealthy.

This is not recorded as a successful GKE end-to-end result. The OCI kind result
remains the completed generic Kubernetes proof. A future GKE rerun should use an
`e2-standard-2` node and wait explicitly for node and Calico readiness before
deploying evidence workloads. That resource change requires separate approval.

## Cleanup and cost

- GKE clusters: absent.
- Compute instances, persistent disks, and external addresses: absent.
- Dedicated Artifact Registry repository and images: absent.
- Dedicated Cloud Build source bucket: absent.
- Temporary service accounts and their bindings: absent.
- KMS version 1: destruction scheduled for 2026-10-19.
- Cloud KMS, Filestore, and Network Connectivity APIs: disabled.
- Container API: still enabled because Cloud Asset retains deleted node-pool
  records in `STOPPING`; API enablement alone has no usage charge.

Measured GKE create-to-delete intervals totaled approximately 0.787 hours. Four
Cloud Builds totaled 188 seconds. Applying the recorded list prices gives an
estimated gross r2 cost of approximately **$0.152 USD**, below the approved
$0.75 cap. Together with the earlier $0.061 evidence run, the known estimated
gross GCP experiment cost is **$0.213 USD**. Actual billing remains pending.

## Post-run changes and validation

- The Helm chart now grants the operator read-only discovery access to
  namespaces and CRDs, matching Kopf's observed startup requirements.
- The lifecycle runner now blocks on node and Calico readiness before creating
  application workloads.
- On OCI (not the local laptop), Helm 3.18.6 lint/render passed; all 45 tests
  passed with 73.11% branch coverage; Ruff, strict mypy, Bandit, Semgrep, and
  pip-audit passed.
