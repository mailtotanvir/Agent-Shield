# GCP Evidence Rerun Approval Request

Status: approved and executed; stopped after bounded diagnostic attempts

## Purpose and boundary

This rerun is limited to completing the interrupted GKE Workload Identity and
Cloud KMS evidence. It does not deploy Temporal to GCP. Temporal is validated on
the existing OCI instance because its managed hosting is unnecessary for this
prototype.

- Project: `redacted-gcp-project` only.
- Zone/region: `northamerica-northeast1-a` / `northamerica-northeast1` only.
- Cluster and repository: `agentshield-evidence-r2`.
- Maximum elapsed lifetime: 90 minutes from the first mutation.
- Hard gross-cost ceiling: **$0.75 USD** before tax.
- No load balancer, Cloud NAT, managed database/Redis/Temporal, GPU, or additional
  VM outside the single GKE node.
- Generated canary only; no personal data or production credential.

## Authorized mutations requested

1. Enable Cloud KMS and any GKE-managed dependency API that is currently
   disabled. The Container API is already enabled.
2. Restore and enable version 1 of the existing dedicated `envelope` CryptoKey;
   do not create another key ring or CryptoKey.
3. Create Docker Artifact Registry repository `agentshield-evidence-r2`, one
   dedicated Cloud Build source bucket, and one Cloud Build/image.
4. Recreate the three dedicated service accounts and only the KMS, Artifact
   Registry, node, and Workload Identity bindings documented in the first run.
5. Create zonal GKE Standard cluster `agentshield-evidence-r2` with one
   on-demand `e2-medium` node, 20 GiB balanced disk, Workload Identity, network
   policy, no managed logging/monitoring, and no Kubernetes LoadBalancer.
6. Deploy the pinned image digest and Helm chart. Apply
   `examples/agent-secret.yaml` using the CRD's validated
   `scopedTo.matchLabels` object shape.
7. Run positive delivery, unauthorized-ServiceAccount denial, ciphertext/API
   inspection, KMS identity, and audit checks. On any rollout failure, capture
   pod status, events, and redacted logs before teardown.
8. Invoke the pre-created idempotent teardown script, then perform the read-only
   inventory it prints. Destroy the restored KMS version and disable APIs enabled
   for this experiment when Google permits it.

The teardown command is:

```bash
AGENTSHIELD_CONFIRM_PROJECT=redacted-gcp-project \
AGENTSHIELD_DISABLE_APIS=true \
scripts/gcp-teardown.sh
```

The script uses explicit project, region, and resource names; removes the exact
IAM bindings before service-account deletion; tolerates already-absent resources;
and ends with GKE, Compute, Artifact Registry, IAM, KMS, Cloud Asset, and API
inventory. Manual billing verification remains required because billing data can
lag.

## Price envelope

For 90 minutes, the previous dated list-price measurements imply approximately:

| Item | Gross USD |
|---|---:|
| GKE management | $0.1500 |
| One e2-medium node | $0.0914 |
| 20 GiB balanced disk | $0.0046 |
| External IPv4 | $0.0075 |
| Cloud Build allowance | $0.0600 |
| KMS, registry, and small evidence allowance | $0.0100 |
| **Expected upper estimate** | **$0.3235** |

The requested $0.75 ceiling allows for startup/deletion rounding without
authorizing more resources or a longer lifetime. Free-tier credits are ignored.

Expected unavoidable residuals are Cloud Build history/logs, delayed billing
records, non-deletable KMS key-ring/CryptoKey metadata, the key version in
`DESTROY_SCHEDULED`, and possibly a temporarily stale Cloud Asset node-pool
record with no backing compute.

Approval phrase:
`Approve the bounded GCP r2 lifecycle in docs/evidence/gcp-rerun-approval-request.md`

## Outcome

The approved lifecycle was executed and stopped within its time and cost caps.
It proved image build/pinning, broker and operator rollout, CRD acceptance,
Workload Identity encryption, and unauthorized-request denial. The complete
authorized path did not pass: the one-node `e2-medium` cluster's Calico/Typha
components were not consistently ready because of CPU pressure, and workload
connections to the Kubernetes API service IP timed out. All billable resources
were deleted. See `gcp-r2-summary.md` for measured details and the next bounded
recommendation.
