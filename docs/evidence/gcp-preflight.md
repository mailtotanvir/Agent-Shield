# GCP Read-only Preflight

Observed: 2026-09-18  
Project: `redacted-gcp-project`  
Selected zone: `northamerica-northeast1-a` (Montréal)  
Mutations performed: none  
Cost incurred by preflight: **$0.00**

## Project facts

- The project is active and billing is enabled.
- The authenticated principal has project Owner and Service Usage Admin. No IAM
  grant is needed for the proposed experiment; the execution must still remain
  inside the explicit approval boundary.
- `artifactregistry.googleapis.com`, `cloudbuild.googleapis.com`, Compute Engine,
  IAM, logging, and monitoring are enabled.
- `container.googleapis.com` and `cloudkms.googleapis.com` are not enabled.
  Enabling them is a mutation and is included only in the proposed lifecycle.
- Organization Policy API is disabled. It was not enabled merely to inspect
  policy; cluster creation will fail closed if an inherited constraint blocks it.
- The default VPC and a default `northamerica-northeast1` subnet exist.
- Regional quota has 24 E2 vCPUs available (0 used), 200 general vCPUs (0 used),
  8 in-use addresses (0 used), and 500 GiB SSD (0 used).
- One unrelated 59 MB Artifact Registry repository exists in `us-central1`; it
  will not be reused or modified.
- Cloud Asset search found no resource named `agentshield`.

Sensitive account, billing-account, and project-number values are intentionally
excluded from this public evidence file.

## Official SKU snapshot

All prices are USD list prices returned by the Google Cloud Billing Catalog on
2026-09-18, effective at `2026-09-18T07:00:00Z`.

| SKU | Description | Unit price |
|---|---|---:|
| `6B92-A835-08AB` | Zonal Kubernetes Clusters | $0.100000/hour |
| `F362-BA10-04D7` | E2 Instance Core running in Montreal | $0.024013380/vCPU-hour |
| `699E-FF84-4093` | E2 Instance RAM running in Montreal | $0.003218160/GiB-hour |
| `5785-6130-358E` | Balanced PD Capacity in Montreal | $0.110000/GiB-month |
| `C054-7F72-A02E` | External IP Charge on a Standard VM, paid tier | $0.005000/hour |
| `E09C-32B3-9AC7` | Active software symmetric KMS key version | $0.060000/month |
| `3BDA-77FB-678B` | Software symmetric cryptographic operations | $0.030000/10,000 operations |
| `8502-299A-ABAF` | Artifact Registry storage, paid tier | $0.100000/GiB-month |
| `A464-9020-6404` | Cloud Build e2-standard-2, paid tier | $0.006000/build-minute |

Catalog endpoints are `cloudbilling.googleapis.com/v1/services/<service>/skus`.
The service IDs used were Compute Engine `6F81-5844-456A`, GKE
`CCD8-9BF1-090E`, KMS `EE2F-D110-890C`, Artifact Registry `149C-F9EC-3994`, and
Cloud Build `8B5D-EF7D-EB12`.

## Limitations

The GKE and KMS APIs are currently disabled, so a read-only API-specific
inventory cannot be queried. Cloud Asset found no AgentShield-named resources,
but this is not proof that no differently named historical resource exists. The
proposal uses unique dedicated names and stops on any name collision.
