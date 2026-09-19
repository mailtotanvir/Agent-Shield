# GCP r3 Selected Evidence

Raw Kubernetes diagnostics were reviewed and discarded after extracting these
results because they contained ephemeral IP addresses, node identifiers, and a
Google support token. No plaintext secret or bearer token is retained.

```text
in-cluster Kubernetes API connectivity verified
EXPECTED_SHA256=50feb889722f84296023ab1011d1f5f83f4bd6ac88fefa94bdd814b3bc5072dd
GENERATION=1
unauthorized request denied with HTTP 403
authorized request reached broker; Cloud KMS decrypt failed; HTTP 503
```

At capture time, the node, Calico daemon, Calico Typha, broker, and operator
were Ready. Ingestion and denial Jobs were Complete. The authorized Job was
Failed because its secret-agent received the broker's sanitized 503 response.

Post-teardown read-only inventories were empty for the cluster, VM, disk,
address, repository, service accounts, and source bucket.
