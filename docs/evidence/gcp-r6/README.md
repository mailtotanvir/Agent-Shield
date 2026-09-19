# GCP r6 Selected Evidence

The run used image digest
`sha256:d4c91b42d6e1dd0cf44568562674348db750d793c39929be5bc5393988a6ae8b`.

Retained sanitized outputs establish this sequence:

```text
in-cluster Kubernetes API connectivity verified
expected broker Workload Identity verified
encrypted generation: 1
authorized memory-volume delivery: matching SHA-256 digest
unauthorized workload: HTTP 403
```

The generated canary plaintext was never printed or retained. Its SHA-256
digest is a one-way comparison value for a randomly generated high-entropy
canary. Raw diagnostics were reviewed and discarded because they contained
ephemeral IP addresses, node identifiers, and a Google support token.

The original runner returned nonzero only because its final text assertion used
an obsolete success phrase. That assertion was corrected after the run; the
cloud lifecycle was not repeated.
