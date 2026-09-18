# GCP One-shot Lifecycle Approval Request

This is a proposal, not authorization. Nothing in this document has been run.

## Boundaries

- Project: `redacted-gcp-project` only.
- Zone/region: `northamerica-northeast1-a` / `northamerica-northeast1` only.
- Maximum elapsed lifetime: four hours from the first API enablement.
- Hard gross-cost stop: **$2.00 USD** before tax.
- No load balancer, Cloud NAT, managed Redis, database, GPU, or VM outside the
  single GKE node.
- Generated canaries only; no production credentials or personal data.

## Proposed resources and names

1. Enable `container.googleapis.com` and `cloudkms.googleapis.com`.
2. Docker Artifact Registry repository `agentshield-evidence`.
3. Cloud KMS key ring `agentshield-evidence`, CryptoKey `envelope`, and its first
   software symmetric key version.
4. Service accounts `agentshield-gke-node`, `agentshield-broker`, and
   `agentshield-ingest`, plus only the bindings listed below.
5. Zonal GKE Standard cluster `agentshield-evidence`: one on-demand `e2-medium`
   node, 20 GiB balanced boot disk, Workload Identity enabled, no managed
   logging/monitoring, no external load balancer.
6. Namespaces `agentshield-system` and `agents`, the Helm release, two generated
   canary jobs, and ephemeral evidence objects.
7. One Cloud Build and one tagged image in the dedicated repository.

The node uses an ephemeral external IPv4 address for package/image access because
the existing subnet has Private Google Access disabled. This avoids modifying the
shared subnet or creating a chargeable Cloud NAT.

## IAM scope

- Node GSA: `roles/container.defaultNodeServiceAccount` and
  `roles/artifactregistry.reader` at project scope, removed at teardown.
- Broker GSA: `roles/cloudkms.cryptoKeyDecrypter` on the test CryptoKey only;
  Workload Identity User granted only to the broker KSA.
- Ingest GSA: `roles/cloudkms.cryptoKeyEncrypter` on the test CryptoKey only;
  Workload Identity User granted only to the one-shot ingest KSA.
- Kubernetes RBAC limits ingest to the named `AgentSecret`/envelope Secret path;
  broker access remains the chart's TokenReview and read-only policy path.

The active user already has sufficient project permissions, so no new user IAM
grant is requested. AgentShield will not self-grant or retain broader roles.

## Four-hour gross estimate

| Item | Calculation | Gross USD |
|---|---:|---:|
| GKE zonal management | 4 h × $0.10 | $0.4000 |
| e2-medium node | 4 h × (2 × $0.02401338 + 4 × $0.00321816) | $0.2436 |
| 20 GiB balanced disk | 20 × $0.11 × 4/730 | $0.0121 |
| external IPv4 | 4 h × paid-tier $0.005 | $0.0200 |
| KMS key version | conservative 24 h × $0.06/730 | $0.0020 |
| 100 KMS operations | 100 × $0.03/10,000 | $0.0003 |
| 70 MiB Artifact Registry image | paid-tier prorated estimate | $0.0001 |
| Cloud Build | maximum 10 paid minutes × $0.006 | $0.0600 |
| small evidence egress contingency | allowance | $0.0200 |
| **Estimated gross maximum for planned use** | | **$0.7581** |

Free-tier credits are deliberately excluded from the gross estimate. The $2 cap
allows for startup rounding and minor telemetry without authorizing extra
resources or a longer run.

## Evidence run

The run builds remotely with Cloud Build, deploys the pinned digest, creates the
key and Workload Identity bindings, encrypts a generated canary in-cluster, and
executes positive and denied paths. It captures sanitized manifests, pod/events,
image digest, ciphertext inspection, Cloud KMS audit correlation, and workload
logs. It scans the evidence for the canary before copying it to the repository.

Stop immediately on unexpected resources, identity broadening, plaintext in a
Kubernetes API object/log, failure to enforce denial, elapsed time over four
hours, or projected gross cost over $2.

## Teardown included in the requested approval

Delete in reverse order: workloads/Helm namespaces and cluster; image and
dedicated Artifact Registry repository; temporary IAM bindings and all three
service accounts; destroy the KMS key version; disable the two APIs only if the
run enabled them and doing so has no discovered dependency.

Cloud KMS key rings and CryptoKey metadata cannot be deleted. The destroyed key
version leaves non-billable metadata as the only expected residual. Final
read-only inventory and delayed billing checks are mandatory.

Approval phrase: `Approve the GCP lifecycle in docs/evidence/gcp-approval-request.md`
