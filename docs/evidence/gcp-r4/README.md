# GCP r4 Selected Evidence

Raw Kubernetes diagnostics were reviewed and discarded after extracting these
results because they contained ephemeral IP addresses, node identifiers, and a
Google support token. No plaintext secret or bearer token is retained.

```text
in-cluster Kubernetes API connectivity verified
broker identity: [redacted-broker-service-account]
EXPECTED_SHA256=f9c922a279b890c091f09aa0faf2b3a9d0af554c252aa7efae36d84f9695953b
GENERATION=1
unauthorized request denied with HTTP 403
authorized decrypt failure class: AttributeError
```

The `AttributeError` was traced to fields that do not exist on the Cloud KMS
`DecryptResponse` schema. The adapter fix was subsequently validated on OCI.
Post-teardown inventories were empty for the cluster, VM, disk, address,
repository, dedicated service accounts, and source bucket.
