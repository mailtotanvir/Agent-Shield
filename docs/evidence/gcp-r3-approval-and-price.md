# GCP r3 Approval and Price Quote

Approved by the user on 2026-09-19 before resource creation.

## Fixed execution boundary

- Project: `redacted-gcp-project`.
- Region/zone: `northamerica-northeast1` / `northamerica-northeast1-a`.
- Dedicated cluster and repository: `agentshield-evidence-r3`.
- One on-demand `e2-standard-4` node with a 20 GiB balanced disk.
- Workload Identity and GKE NetworkPolicy remain enabled.
- No LoadBalancer, Cloud NAT, managed database, Redis, Temporal, or GPU.
- One build and one evidence attempt.
- A 45-minute watchdog sends `TERM`; the exit trap immediately runs the
  idempotent teardown script.
- Gross list-price cap: **$0.35 USD**, excluding tax and ignoring free tiers.

## Google Cloud Billing Catalog quote

Queried through the official Cloud Billing Catalog immediately before r3 on
2026-09-19. The catalog prices were effective at `2026-09-18T07:00:00Z`.

| SKU | Description | Paid-tier unit price |
|---|---|---:|
| `6B92-A835-08AB` | Zonal Kubernetes Clusters | $0.100000/hour |
| `F362-BA10-04D7` | E2 Instance Core running in Montreal | $0.024013380/vCPU-hour |
| `699E-FF84-4093` | E2 Instance RAM running in Montreal | $0.003218160/GiB-hour |
| `5785-6130-358E` | Balanced PD Capacity in Montreal | $0.110000/GiB-month |
| `C054-7F72-A02E` | External IP on a Standard VM | $0.005000/hour after free tier |
| `E09C-32B3-9AC7` | Active software symmetric KMS key version | $0.060000/month |
| `3BDA-77FB-678B` | Software symmetric cryptographic operations | $0.030000/10,000 |
| `8502-299A-ABAF` | Artifact Registry storage | $0.100000/GiB-month after free tier |
| `A464-9020-6404` | Cloud Build e2-standard-2 | $0.006000/build-minute after free tier |

## Forty-five-minute maximum estimate

| Item | Calculation | Gross USD |
|---|---|---:|
| GKE management | 0.75 h × $0.10 | $0.0750 |
| e2-standard-4 CPU | 4 × 0.75 h × $0.024013380 | $0.0721 |
| e2-standard-4 RAM | 16 GiB × 0.75 h × $0.003218160 | $0.0386 |
| 20 GiB balanced disk | 20 × $0.11 × 0.75/730 | $0.0023 |
| External IPv4 | 0.75 h × $0.005 | $0.0038 |
| Cloud Build allowance | 10 min × $0.006 | $0.0600 |
| KMS, operations, and registry | conservative allowance | $0.0002 |
| **Quoted maximum** | | **$0.2520** |

Headroom below the approved cap is **$0.0980**. The runner refuses to mutate
if its embedded quote exceeds the cap. Actual billing is recorded separately
after teardown because Google billing export can lag.

## Evidence and teardown

Before application deployment, the runner waits for the node, Calico daemon,
and Calico Typha deployment, then proves pod-to-Kubernetes-API connectivity.
It captures ciphertext-only storage, authorized digest equality, unauthorized
HTTP 403, Workload Identity/KMS behavior, and KMS audit evidence. Any success,
failure, interrupt, or watchdog expiry invokes teardown.

## Outcome

The one approved attempt ran and was torn down. Infrastructure readiness,
in-cluster API connectivity, KMS ingestion, and the denial path passed. The
authorized path reached the broker but failed during KMS decryption. See
`gcp-r3-summary.md`. The r3 runner now refuses reuse of the consumed approval.
