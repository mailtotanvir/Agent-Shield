# GCP r5 Selected Evidence

Raw diagnostics were reviewed and discarded after extracting these facts
because they contained ephemeral IP addresses, node identifiers, and a Google
support token. No plaintext secret or bearer token is retained.

```text
cluster: RUNNING
node: Ready
calico-node: rollout initially complete
calico-typha: rollout initially complete
kubernetes-api-connectivity pod: Error, exit code 1
AgentShield deployment: not started
```

Events showed GKE replacing the initial Calico node and Typha pods while the
connectivity pod was starting. The probe's own log was not retained, so its
exact exception is unknown. Post-teardown inventories were empty for the
cluster, VM, disk, address, repository, dedicated service accounts, and source
bucket.
