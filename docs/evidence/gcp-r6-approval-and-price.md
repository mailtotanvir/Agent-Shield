# GCP r6 Approval and Price Quote

Approved by the user on 2026-09-19 before resource creation.

## Fixed execution boundary

- Project: `redacted-gcp-project`.
- Region/zone: `northamerica-northeast1` / `northamerica-northeast1-a`.
- Dedicated cluster and repository: `agentshield-evidence-r6`.
- One on-demand `e2-standard-4` node and one 20 GiB balanced disk.
- Workload Identity and GKE NetworkPolicy enabled.
- No load balancer, Cloud NAT, managed database, Redis, Temporal, or GPU.
- One image build and one validation attempt.
- 25-minute watchdog and automatic teardown on every exit path.
- Gross list-price cap: **$0.25 USD**, excluding tax and ignoring free tiers.

## Fresh Google Cloud Billing Catalog quote

Queried from the official catalog at `2026-09-19T05:18:51Z`. Prices were
effective at `2026-09-18T07:00:00Z`.

| SKU | Description | Paid-tier unit price |
|---|---|---:|
| `6B92-A835-08AB` | Zonal Kubernetes Clusters | $0.100000/hour |
| `F362-BA10-04D7` | E2 Instance Core in Montreal | $0.024013380/vCPU-hour |
| `699E-FF84-4093` | E2 Instance RAM in Montreal | $0.003218160/GiB-hour |
| `5785-6130-358E` | Balanced PD Capacity in Montreal | $0.110000/GiB-month |
| `C054-7F72-A02E` | External IP on a Standard VM | $0.005000/hour after free tier |
| `E09C-32B3-9AC7` | Active software symmetric KMS key version | $0.060000/month |
| `3BDA-77FB-678B` | Software symmetric cryptographic operations | $0.030000/10,000 |
| `8502-299A-ABAF` | Artifact Registry storage | $0.100000/GiB-month after free tier |
| `A464-9020-6404` | Cloud Build e2-standard-2 | $0.006000/build-minute after free tier |

## Twenty-five-minute maximum estimate

| Item | Gross USD |
|---|---:|
| GKE management | $0.0417 |
| e2-standard-4 CPU | $0.0400 |
| e2-standard-4 RAM | $0.0215 |
| 20 GiB balanced disk | $0.0013 |
| External IPv4 | $0.0021 |
| Cloud Build, ten-minute allowance | $0.0600 |
| KMS, operations, and registry allowance | $0.0002 |
| **Quoted maximum** | **$0.1667** |

Headroom below the approved cap is **$0.0833**. Free tiers and credits are not
used to reduce the estimate. R6 requires three consecutive dataplane-readiness
observations over 20 seconds, retries the in-cluster API probe for up to one
minute, and captures its log immediately on terminal failure.

## Outcome

The approved run completed the intended security path. The API preflight,
Workload Identity check, KMS-backed ingestion, authorized memory-volume
delivery, digest verification, and unauthorized HTTP 403 check all passed. The
runner then exited nonzero because its final assertion expected an obsolete
success phrase; the retained authorized-job output proves the actual check had
already passed. The assertion was corrected after the run and was not used to
justify another cloud attempt. Automatic teardown removed all billable
resources; see `gcp-r6-summary.md`.
