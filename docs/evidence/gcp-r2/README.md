# GCP r2 Selected Evidence

These are deliberately small, publishable extracts from the approved GCP r2
run. Raw diagnostics were reviewed locally, summarized here, and discarded
because they contained ephemeral IP addresses, node names, and noisy system
events. No plaintext secret or bearer token is retained.

## Successful partial assertions

- Broker and operator deployments reached `Available`.
- The corrected `AgentSecret` resource was accepted and reconciled.
- `ingest.log` records the expected plaintext digest and encrypted-secret
  generation from the successful Workload Identity/KMS attempt. It contains no
  plaintext.
- A ServiceAccount outside the allowed selector received HTTP 403.

## Final-attempt failure evidence

```text
pod/agentshield-ingest-*/ingest: TimeoutError: Connect call failed
pod/agentshield-ingest-*/ingest: ClientConnectorError: Cannot connect to the
Kubernetes API service on port 443
kube-system/calico-typha: 0/1 nodes are available: 1 Insufficient cpu
kube-system/calico-node: 0/1 Ready
```

The one-node `e2-medium` cluster did not have a consistently healthy network
dataplane. This run therefore does not claim the authorized GKE delivery path
passed.

## Teardown verification

```text
GKE clusters: []
Compute instances: []
Persistent disks: []
External addresses: []
Artifact Registry repositories in the run region: []
Dedicated service accounts: []
Dedicated source buckets: []
KMS key version 1: DESTROY_SCHEDULED (2026-10-19)
Container API: enabled; disable blocked by stale deleted-node-pool assets
```

API enablement has no usage charge. See `../gcp-r2-summary.md` for timings,
cost, and the complete interpretation.
