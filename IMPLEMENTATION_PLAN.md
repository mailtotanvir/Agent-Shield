# AgentShield Implementation and Evidence Plan

Status: implementation active; OCI validation passed; first GCP run torn down
Project: `redacted-gcp-project`  
Repository: <https://github.com/mailtotanvir/Agent-Shield>  
Prepared: 2026-09-18  
Cloud resources created while preparing this plan: none  
Cost incurred while preparing this plan: **$0.00**

## 1. Objective

Build the security-focused Python library and Kubernetes operator defined in
`design.md`, validate portable Kubernetes behavior on the existing OCI
instance, then run only the smallest necessary GCP
experiment to prove GKE Workload Identity and Cloud KMS integration. Preserve a
reproducible evidence packet suitable for an article in
`mailtotanvir.github.io`, and tear down every temporary service after the evidence
has been copied and verified.

This plan deliberately separates implementation from paid-cloud validation. Most
of AgentShield can and should be built without a live GCP resource.

## 2. Non-negotiable authority boundary

Terra must not create, enable, update, deploy, restart, scale, or delete any GCP
service or VM without Tanvir's explicit approval. The prohibition includes, but
is not limited to:

- enabling Google APIs;
- creating a GKE cluster or node pool;
- creating KMS key rings, keys, or key versions;
- creating Artifact Registry repositories or pushing images;
- changing IAM policies, service accounts, Workload Identity bindings, firewall
  rules, quotas, budgets, or billing configuration;
- deploying AgentShield or any supporting workload to GCP; and
- tearing down GCP resources.

Read-only discovery is allowed. Before each requested approval, Terra must show
the exact project, region/zone, resource names, commands or manifests, expected
lifetime, gross price estimate, maximum spend, teardown commands, and residual
resources. Approval for one resource bundle does not imply approval for a later
bundle. Never silently switch projects; every GCP command must specify
`--project=redacted-gcp-project` or use an equally explicit project field.

OCI is the test environment, not a substitute for GKE-specific proof. Use the
existing instance through `~/oci.sh` for isolated temporary validation. Do not
install Kubernetes system-wide or change firewall rules. Keep test tools and
state under `/tmp`, use disposable kind, and remove them after evidence is
copied and verified.

## 3. Accepted design decisions

`design.md` resolves the ambiguities and controls the initial implementation:

1. secrets use an authenticated broker, pod-bound ServiceAccount identity, an
   explicit sidecar, and a memory-backed volume; plaintext is not stored in etcd;
2. AgentShield is an RFC 8693 client/policy layer, not an authorization server;
3. external identity providers own signing, JWKS publication, and issuer
   recovery; AgentShield owns strict verification and rotation/cache behavior;
4. Google OIDC, IAP validation, and GKE Workload Identity are separate adapters;
5. DPoP is implemented first and fails closed for policy-labelled sensitive
   scopes and actions; and
6. refresh-token persistence is optional and uses a minimal KMS-encrypted Redis
   vault with atomic rotation and token-family reuse response; and
7. Temporal optionally coordinates durable secret rotation using reference-only
   workflow history, idempotent activities, verification, and compensation.

## 4. Delivery strategy

### Stage 0 — Baseline and scaffold (validation on OCI, $0 incremental)

- Initialize the repository and implement the structure in the spec.
- Use Python 3.12+, `uv` or a locked equivalent, Ruff, mypy, pytest, Bandit,
  Semgrep, pip-audit, and Trivy.
- Add `SECURITY.md`, a responsible-disclosure path, ADR template, threat-model
  template, and a test-fixture policy that forbids real credentials.
- Add CI with least privileges, pinned actions, dependency caching, SBOM output,
  and artifact retention limits.
- Establish coverage gates around validation and authorization decisions rather
  than chasing a repository-wide percentage alone.

Exit evidence: clean install, lint/type/test/SAST reports, dependency lock/SBOM,
initial STRIDE model, and implementation conformance with `design.md`.

### Stage 1 — Identity connectors (validation on OCI, $0 incremental)

- Implement immutable Pydantic token/claim models and the connector protocol.
- Build Generic OIDC first, then thin Entra and Google adapters.
- Implement authorization code + PKCE, client credentials, refresh, revocation,
  introspection, and device authorization only when supported by provider
  metadata.
- Enforce discovery issuer matching, redirect URI/state handling, PKCE S256,
  bounded HTTP timeouts, TLS verification, JWKS cache limits, and error
  sanitization.
- Test against deterministic fakes/containers on OCI. Live Google OAuth setup is a
  later, separately approved experiment if it adds evidence beyond protocol
  tests.

Exit evidence: protocol contract tests, malicious/malformed provider tests,
redacted structured logs, and a captured PKCE sequence diagram.

### Stage 2 — Session manager (validation on OCI, $0 incremental)

- Implement the seven-step JWT validation pipeline with an explicit algorithm
  allowlist; reject `none`, HS256, algorithm confusion, duplicate/invalid claims,
  stale JWKS, wrong issuer/audience, and unreasonable clock values.
- Implement bounded JWKS caching and safe refresh-on-unknown-`kid` behavior that
  resists refresh storms.
- Define a pluggable revocation interface and implement Redis. Run Redis in a
  disposable OCI container for tests; do not provision Memorystore.
- Implement token rotation/reuse detection and the selected proof-of-possession
  mechanism after its ADR is accepted.
- Use property/fuzz tests for parser and claim-boundary behavior and concurrency
  tests for the 500 ms revocation target.

Exit evidence: latency distribution for revocation propagation, key-rotation
trace, adversarial token matrix, and logs proving sensitive claims are hashed or
removed.

### Stage 3A — Operator and envelope encryption (kind on OCI, $0 incremental)

- Implement the CRD with OpenAPI validation, status conditions, finalizers,
  idempotent reconciliation, retry/backoff, and safe deletion behavior.
- Implement AES-256-GCM with a fresh random DEK and nonce per encryption,
  authenticated metadata, versioned envelopes, and zeroization where Python
  permits it. Make KMS adapters narrow and injectable.
- Implement the no-plaintext ingestion CLI, ciphertext-envelope storage,
  authenticated broker, TokenReview/pod-policy checks, explicit sidecar, and
  atomic delivery to a memory-backed volume exactly as defined in `design.md`.
- Implement a deterministic fake KMS for unit/integration tests; it must be
  impossible to select in a production chart accidentally.
- Generate least-privilege namespaced RBAC where possible. Test allowed and
  denied ServiceAccounts, cross-namespace access, selector changes, rotation,
  KMS failure, malformed ciphertext, reconciliation retry, and uninstall.
- Package and test the Helm chart on a disposable kind cluster.

Exit evidence: CRD/RBAC manifests, Helm lint/template output, kind test logs,
Kubernetes audit events, ciphertext inspection, and negative-access recordings.

### Stage 3B — OCI portability run (completed; incremental cloud cost $0)

First perform a read-only survey through `~/oci.sh`: OS, architecture, OCI shape,
CPU/RAM/disk, existing services, ports, firewall, Kubernetes/container runtime,
and whether the instance is billed regardless of this project. Redact IPs, keys,
usernames, and unrelated service data from retained artifacts.

Use a disposable kind cluster named `agentshield-evidence` without installing a
system-wide Kubernetes distribution. A single-node OCI run can prove Helm and
generic Kubernetes portability; it cannot prove GKE Workload Identity, GKE
control-plane behavior, availability, or production resilience.

Exit evidence: sanitized cluster/host facts, conformance matrix versus kind,
operator test output, and complete namespace/uninstall cleanup proof.

### Stage 3C — GCP preflight and priced approval packet (read-only, $0)

With explicit project flags, collect without mutation:

- active account and accessible project number for `redacted-gcp-project`;
- billing attachment and relevant free-tier/credit status, without exposing
  billing identifiers publicly;
- enabled APIs, IAM permissions, org policies, quotas, candidate zones, and
  available machine types;
- existing GKE, KMS, Artifact Registry, VPC/subnet, service account, and similarly
  named resources so the plan neither collides nor bills duplicates;
- current official SKU prices for the selected region and date.

Produce an approval packet for the smallest viable experiment. Preferred default
if discovery supports it: one **zonal GKE Standard** cluster, one small on-demand
node, no external load balancer, no Cloud NAT created solely for the test, no
managed Redis, minimal boot disk, log volume capped, and a hard experiment window
of four hours. Reuse an existing suitable Artifact Registry/KMS/VPC only after
showing that reuse does not risk unrelated workloads or teardown.

Do not run any mutating command until Tanvir explicitly approves this packet. For
the one-shot implementation, request one bounded lifecycle approval covering
creation, the evidence run, and exact reverse-order teardown. A new resource,
higher cap, broader IAM role, or changed command needs supplemental approval.

### Stage 3D — Approved GKE/KMS evidence run (paid, approval required)

Only after the lifecycle packet is approved:

1. Start the cost ledger and capture creation timestamps/resource labels.
2. Create only the approved resources, labeled at minimum with
   `project=agentshield`, `purpose=blog-evidence`, `owner=tanvir`, and an expiry
   timestamp where supported.
3. Configure Kubernetes-to-Google Workload Identity with a dedicated Google
   service account and only the minimum KMS encrypt/decrypt permissions on the
   test key.
4. Deploy a pinned-image/tag-or-digest AgentShield chart.
5. Run the same conformance suite as kind plus GKE-specific identity and KMS
   cases: positive encrypt/decrypt, unauthorized ServiceAccount denial, removed
   binding denial, key-version behavior, pod recreation, and audit correlation.
6. Avoid processing real credentials or personal data. Use generated canary
   values and verify that none appear in logs, manifests, screenshots, shell
   history artifacts, or Kubernetes API objects contrary to the chosen design.
7. Export sanitized logs, events, metrics, command transcript, manifests, image
   digest/SBOM, KMS audit evidence, timestamps, and price snapshots locally.
8. Stop the experiment if the time/spend ceiling, unexpected resource creation,
   or security invariant is breached.

Before creating any resource, validate `scripts/gcp-teardown.sh` and keep its
exact invocation in the run transcript. All experiment resources use its fixed
names. Teardown is one idempotent command followed by read-only GKE, Compute,
Artifact Registry, IAM, KMS, Cloud Asset, enabled-API, and billing verification.
API disablement is opt-in because APIs that predated a run must not be disabled.
The teardown script's nonzero exit is a prompt for manual cleanup, not permission
to broaden deletion targets.

### Stage 4 — Authorization bus (validation on OCI, $0 incremental)

- Implement the RFC 8693 client/policy boundary, provider-native actor-claim
  validation, audience restrictions, scope intersection (never union), expiry
  non-extension, and revocation linkage. Do not mint tokens or invent a portable
  `agent_chain` claim.
- Test confused-deputy cases, audience substitution, actor-claim tampering,
  replay, scope escalation, expiry extension, and concurrent revocation.
- Integrate connectors only through stable interfaces and preserve full decision
  reasons in redacted audit events.

Exit evidence: delegation sequence, policy decision table, attack/denial matrix,
and trace linking a user token to a safely narrowed agent token.

### Stage 5 — Integration, release, and publication

- Build a minimal FastAPI example and Docker Compose environment; validate them
  on OCI, never on Tanvir's laptop.
- Run full unit, integration, security, packaging, Helm, upgrade, and uninstall
  tests from a clean checkout.
- Publish packages only after a separate release review; PyPI and chart publishing
  are external mutations and are not implicit in this plan.
- Produce source Markdown plus a standalone responsive HTML article compatible
  with the current `mailtotanvir.github.io` style. Do not edit that separate
  repository until publication is explicitly requested.

## 5. Price policy and cost ledger

Every infrastructure decision must record both the estimate made before creation
and the realized cost evidence after teardown. Never report “free” without also
recording gross list price and the credit/free-tier assumption.

Use `docs/evidence/cost-ledger.csv` with these columns:

```text
observed_at_utc,project,provider,region,resource,sku,quantity,unit,
unit_price_usd,estimated_hours,estimated_gross_usd,credit_assumption,
approved_cap_usd,created_at_utc,deleted_at_utc,realized_gross_usd,
realized_net_usd,price_source,evidence_path,notes
```

Maintain `docs/evidence/resource-inventory.yaml` alongside it with resource IDs,
labels, dependency order, creation/deletion commands, and final verification
status. Billing export can lag, so mark realized figures `pending` until billing
data settles and amend the ledger rather than guessing.

### Provisional planning estimate — not authorization and not a quote

The following is only a scale estimate. Terra must replace it with dated official
regional SKUs during Stage 3C.

| Item | Planning assumption | Approximate gross cost |
|---|---|---:|
| GKE Standard management | Common published list rate of $0.10/cluster-hour | $0.40 for 4 h |
| One small GCE node + boot disk | Region and type TBD; use a provisional $0.07-$0.12/hour all-in band | $0.28-$0.48 for 4 h |
| Cloud KMS software key | Common published active-version rate around $0.06/month, prorating/billing rules to verify | <= $0.06 plus operations |
| KMS operations | Small test count; exact SKU and free allowance to verify | typically <$0.01 |
| Image storage/logging/network | Keep image and logs small; avoid internet egress/LB/NAT | target <$0.10 |
| **Four-hour experiment envelope** | Before taxes; gross, before any GKE credit | **planning target $0.75-$1.05** |

Set the proposed approval cap no lower than the exact computed estimate and no
higher than **$2.00** unless Tanvir approves a revised packet. The cap is a stop
condition, not a guarantee from Google. Official sources to snapshot at execution
time: GKE pricing, Compute Engine VM/disk pricing, Cloud KMS pricing, Artifact
Registry pricing, Cloud Logging pricing, and the Google Cloud Pricing Calculator.

## 6. Evidence packet and blog acceptance criteria

Store raw private evidence outside public paths and publish only reviewed,
sanitized derivatives. The packet should contain:

- `run-manifest.json`: git commit, dependency lock hash, image digest, cluster
  versions, test matrix, start/end timestamps, and artifact checksums;
- `commands.ndjson`: commands, timestamps, exit status, and sanitized output;
- test/JUnit, coverage, lint, SAST, dependency, SBOM, Helm, and Trivy reports;
- redacted Kubernetes events/audit logs and KMS audit correlation;
- the preflight estimate, approval record, cost ledger, billing follow-up, and
  teardown inventory;
- diagrams for OIDC/PKCE, JWT validation, envelope encryption, Workload Identity,
  and delegated authority;
- screenshots or a replay that show both allowed and denied paths without cloud
  identifiers or secrets; and
- a limitations section clearly separating protocol/unit tests, single-node OCI,
  and GKE
  claims.

The article should match the strongest pattern in the existing site: a quantified
hero section, the problem and architecture, a concrete failure or uncomfortable
result, evidence-backed fixes, a concise results table, cost and teardown facts,
what changed during implementation, limitations, code/evidence links, and a clear
lesson. Each security post also needs working code, “what goes wrong,” and “what
to check in review” sections as required by the design.

Do not manufacture a clean narrative. A failed control or revised design is
valuable evidence if the original result and correction are preserved.

## 7. Teardown runbook and definition of done

Teardown is included in the approved GCP lifecycle packet and begins immediately
after the evidence copy passes checksum and readability checks. If deletion
was omitted from approval or its target differs, stop and request approval rather
than leaving resources running. Delete in reverse dependency order using the
exact approved inventory:

1. Helm release and evidence namespace;
2. GKE workloads and cluster/node resources;
3. test-only Workload Identity/IAM bindings and service accounts;
4. test-only KMS key material/key ring where Google permits deletion, otherwise
   disable/destroy key versions and record scheduled/persistent remnants;
5. test-only image repository/images, disks, addresses, load balancers, firewall
   rules, and other discovered dependents; and
6. APIs enabled solely for the experiment, but only if disabling them cannot
   affect existing project workloads.

Verify with read-only inventory queries that no labeled resources, unattached
disks, addresses, forwarding rules, load balancers, node pools, clusters, test
service accounts, IAM bindings, KMS versions, images, or log sinks remain. Record
anything that cannot be deleted, its future charge, owner, and expiry action.
Repeat the cost check after billing data settles.

The project is complete only when:

- all scoped functionality and adversarial tests pass from a clean checkout;
- security claims are supported by retained evidence;
- exact estimated and realized prices are recorded;
- all temporary OCI/GCP resources are removed or explicitly documented as an
  accepted residual;
- the public evidence packet is sanitized and its links work; and
- the article accurately distinguishes demonstrated behavior from future work.

## 8. Terra's first handoff actions

Terra should treat this as one continuous implementation run, keeping builds and
tests off Tanvir's laptop:

1. Re-read `design.md` and this plan; echo the GCP authority boundary in
   the work log.
2. Inventory the local repository, initialize/scaffold it, and configure
   `git@github.com:mailtotanvir/Agent-Shield.git` as `origin` without touching
   GCP or OCI. Verify the destination before the first push.
3. Treat `design.md` as the accepted ADR set, draft the STRIDE model, then
   implement Stage 0.
4. Create the empty evidence/cost-ledger templates and automated sanitization
   checks from the start.
5. Continue through OCI-backed stages without waiting for phase-by-phase permission.
   Report verification results, changed files, and current cost at meaningful
   milestones. Pause only for a material design conflict, OCI mutation approval,
   the priced GCP lifecycle approval, or missing GCP IAM permissions.

If the executing identity lacks a GCP permission, Terra reports the exact denied
permission and narrowest suitable predefined or custom role for Tanvir to grant.
Terra must not self-grant access or broaden a role. Once approved, it proceeds
directly through the GCP experiment, evidence capture, and teardown.

The earliest legitimate GCP action is the read-only Stage 3C preflight. The
earliest legitimate GCP mutation is after Tanvir approves its exact priced packet.
