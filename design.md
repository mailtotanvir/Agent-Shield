# AgentShield Design

Status: accepted redesign for prototype completion
Date: 2026-09-18  
Repository: <https://github.com/mailtotanvir/Agent-Shield>  
Authority: this document resolves the open design questions in
`IMPLEMENTATION_PLAN.md` and is the authoritative product and security design.

## 1. Product boundary

AgentShield is a security toolkit for **client agents**. It has four runtime
roles:

1. an OAuth/OIDC client and strict token/session validation library;
2. a policy layer around externally issued tokens and RFC 8693 token exchange;
3. a Kubernetes operator and authenticated broker that delivers KMS-protected
   secrets to authorized agent pods without storing plaintext in etcd; and
4. an optional Temporal worker that durably coordinates secret rotation across
   credential providers, KMS, Kubernetes, verification, and revocation.

AgentShield is not an identity provider, general authorization server, service
mesh, or full secrets platform. The configured identity provider remains the
issuer and authority for access, refresh, and exchanged tokens.

The initial success criterion is an agent workload that can authenticate through
an external OIDC provider, obtain and validate appropriately scoped tokens,
receive an authorized secret in Kubernetes, rotate both safely, and leave a
redacted audit trail. Positive and denied paths must be demonstrated on a disposable
cluster and the GKE-specific identity/KMS path on GKE when approved.

The prototype does not need production availability. Documentation must clearly
separate demonstrated behavior from the production-hardening backlog.

## 2. Component model

```text
External OIDC / OAuth authorization server
       │ discovery, authorize, token, revoke, JWKS, RFC 8693
       ▼
AgentShield identity + session library ─── Redis token/replay state
       │ validated TokenSet / policy decision
       ▼
Client agent

Temporal rotation workflow (optional control plane)
       │ opaque references, versions, digests, policy; never plaintext
       ├── credential-provider activity
       ├── envelope/KMS activity
       ├── delivery-verification activity
       └── old-credential revocation + redacted audit

Agent pod (bound ServiceAccount token)
       │ TLS + authenticated secret request
       ▼
AgentShield secret broker ── TokenReview / Pod lookup ── Kubernetes API
       │
       ├── ciphertext envelope ── Kubernetes Secret / AgentSecret status
       └── wrapped DEK decrypt ── cloud KMS
       │
       ▼
AgentShield sidecar ── atomic file update ── memory-backed shared volume
       │
       ▼
Client agent reads a file; plaintext never enters a Kubernetes API object
```

The Kopf controller and secret broker may share a deployment and codebase, but
they have separate Kubernetes service accounts and permissions. Compromise of
the reconciler must not automatically grant permission to authenticate workload
requests, and the broker receives only the KMS and read permissions it needs.
The Temporal worker is a separate deployment and identity. Installing it is
optional; the broker and manual rotation path remain usable without Temporal.

## 3. ADR-001 — Secret delivery uses an authenticated broker and sidecar

### Decision

Use an in-cluster HTTPS secret broker and an explicitly configured
`agentshield-secret-agent` sidecar. The sidecar writes plaintext to a shared
memory-backed `emptyDir` volume (`medium: Memory`) as an atomically replaced,
read-only application file.

The initial release will not implement a CSI driver or automatic admission
webhook injection. The Helm library provides a reusable pod-template fragment;
users opt into the sidecar visibly in workload manifests.

### Secret ingestion and rotation

An `AgentSecret` never accepts plaintext in `spec` or `status`. After creating
the policy resource, an authorized operator runs `agentshield secret put` with
the value on standard input or through a non-logging file descriptor. The CLI:

1. generates a fresh DEK and nonce locally;
2. encrypts the value locally with AES-256-GCM and binds immutable resource
   identity, schema version, and generation as AAD;
3. calls KMS Encrypt to wrap the DEK; and
4. writes only the versioned envelope to an operator-owned Kubernetes Secret,
   using optimistic concurrency and an owner reference to the `AgentSecret`.

The CLI process briefly holds plaintext; the API server, controller, and etcd do
not. Shell arguments and temporary disk files are forbidden. The writer identity
gets KMS encrypt permission but not decrypt permission. The broker identity gets
decrypt permission but cannot modify envelopes or policy.

`agentshield secret rotate` repeats this flow with a new value and generation.
The controller can schedule reminders and invoke an explicitly configured
rotation-provider plugin, but it cannot invent or rotate a third-party API
credential on its own. Without such a plugin, `intervalHours` means a rotation is
due and produces a condition/notification; it must not falsely report credential
rotation. KMS key-version rotation and DEK rewrapping are tracked separately from
source-credential rotation.

### Request and authorization flow

1. The sidecar receives a projected, short-lived, pod-bound ServiceAccount token
   with audience `agentshield-broker`; the token is not the pod's default broad
   API token.
2. It connects to the broker over TLS and requests an `AgentSecret` by namespace
   and name. The bearer token is never placed in a URL or log.
3. The broker calls Kubernetes `TokenReview`, requires the expected audience,
   validates expiry and pod-bound claims, and extracts namespace,
   ServiceAccount, and pod identity.
4. If `spec.access.scopedTo` contains selectors, the broker reads that exact pod
   and checks its UID, namespace, ServiceAccount, and labels. It does not trust
   caller-supplied labels.
5. The broker authorizes the identity against
   `spec.access.allowedServiceAccounts` and optional selectors. Default is deny.
   Cross-namespace references are rejected.
6. The broker reads the versioned ciphertext envelope, asks the selected KMS to
   unwrap its DEK, authenticates metadata as AES-256-GCM AAD, decrypts in memory,
   and returns the value over TLS with `Cache-Control: no-store`.
7. The sidecar writes a mode `0400` temporary file on the memory-backed volume,
   `fsync`s where applicable, atomically renames it, and clears replaceable
   buffers. The application volume mount is read-only.
8. The sidecar watches or polls the non-secret envelope version with bounded
   jitter and repeats delivery after rotation. It retains the last valid file on
   transient failure and fails readiness after the configured staleness limit.

### Storage and cleanup claims

- Kubernetes etcd stores the CRD, policy metadata, nonce, ciphertext, encrypted
  DEK, algorithm/version metadata, and hashes. It never receives plaintext.
- The broker holds plaintext only during a request. Python cannot guarantee
  complete memory zeroization, so documentation must say “best-effort buffer
  clearing,” not “zero memory residue.”
- The node holds plaintext in RAM-backed tmpfs and the agent/sidecar process
  memory. Processes with sufficient pod/node privileges can read it; the threat
  model must state this.
- Pod termination removes the tmpfs volume. The sidecar also unlinks files on
  graceful shutdown. Forced node loss relies on memory disappearance.
- Plaintext must never appear in environment variables, Kubernetes Secrets,
  events, status, metrics, traces, error strings, core dumps, or command lines.

NetworkPolicy limits broker ingress to opted-in namespaces. Resource limits,
maximum response size, timeouts, request concurrency, and audit rate controls are
mandatory. Audit records contain request ID, hashed subject, resource identity,
decision/reason code, envelope version, and latency—never the token, secret,
claims, ciphertext, or encrypted DEK.

### Why this option

This proves Kubernetes workload identity, bound-token validation, RBAC, policy
enforcement, KMS envelope encryption, rotation, atomic delivery, denial, and
cleanup. It preserves “no plaintext in etcd” while remaining implementable in
Python. A CSI driver adds a node-level Go/gRPC surface that distracts from the
client-agent goal; a materialized Kubernetes Secret invalidates the etcd claim.

## 4. ADR-002 — AgentShield is an RFC 8693 client and policy layer

### Decision

AgentShield does not expose a token endpoint and does not mint access or refresh
tokens. `TokenExchangeClient` calls a configured external authorization server's
RFC 8693 endpoint. `DelegationPolicy` validates the requested exchange before the
call and the returned token before releasing it to the agent.

The policy requires:

- an issuer and token endpoint selected from pinned configuration/discovery;
- requested scopes to be a subset of the subject token's effective scopes and a
  configured per-agent allowlist;
- a requested audience/resource in the agent's allowlist;
- returned issuer, audience, subject relationship, scope, expiry, and proof
  binding to satisfy policy; and
- returned expiry not to exceed the configured maximum or the remaining subject
  token lifetime.

External providers represent delegation differently. AgentShield keeps a local
hash chain of token fingerprints and policy decisions, optionally anchored to an
external immutable audit sink, and validates provider-native actor claims such
as `act` when present. Without an external anchor, the chain detects accidental
or unsophisticated alteration but is not claimed to resist an administrator who
can rewrite both events and hashes. AgentShield must not claim a portable
`agent_chain` JWT claim unless the external issuer signs it.

If the provider lacks RFC 8693, the connector reports it as unsupported.
AgentShield does not emulate exchange by signing a token.

### Consequence

The original specification's “JWT issuance” and AgentShield-owned
`agent_chain` are out of scope initially. The session manager manages externally
issued token lifecycles; it does not become an authorization server. This keeps
the project focused on secure client agents and avoids a lightly implemented
second trust authority.

## 5. ADR-003 — External issuers own token signing and JWKS publication

### Decision

The external OIDC/OAuth provider owns issuer identity, token-signing private
keys, JWKS publication, key rotation, compromise response, and recovery.
AgentShield owns strict verification and cache behavior.

AgentShield:

- pins the issuer and allowed asymmetric algorithms (`ES256` and `RS256`); it
  never accepts an algorithm from token input as policy;
- rejects `none`, HMAC algorithms, attacker-supplied key URLs, and keys whose
  type/use/algorithm do not match;
- fetches discovery and JWKS only from configured HTTPS origins with bounded
  size, timeout, redirects, and cache lifetime;
- caches by issuer and `kid`, honors a bounded TTL, refreshes once on unknown
  `kid`, and coalesces concurrent refreshes;
- accepts an old key only while it remains published and the token validates;
  and
- fails closed when a required key is unavailable. Stale-key grace is off by
  default and must be short, observable, and explicitly risk-accepted if enabled.

Provider recovery means revoking affected sessions, invalidating caches,
fetching new metadata/JWKS, and requiring reauthentication according to policy.
Tests use a local issuer that rotates asymmetric keys; its fixture private keys
can never be selected in production.

This option still demonstrates secure discovery, rotation, algorithm-confusion
defense, caching, outage behavior, and recovery without turning AgentShield into
an issuer. DPoP proof keys are client possession keys, not token-signing keys.

## 6. ADR-004 — Google integrations are separate adapters

Implement three explicitly separate boundaries:

1. `GoogleOIDCConnector` uses Google Accounts or a configured Google Identity
   Platform tenant and validates its exact issuer and audience.
2. `GoogleIAPTokenValidator` validates assertions for IAP-protected resources. It
   is not an interactive OIDC connector and applies IAP-specific rules.
3. GKE Workload Identity authenticates the Kubernetes broker to Cloud KMS. It is
   infrastructure identity, not end-user or agent OAuth.

Configuration types, discovery, tests, and documentation must not use “Google
Identity,” “Identity Platform,” and “IAP” interchangeably.

## 7. ADR-005 — DPoP is the first proof-of-possession mechanism

Implement OAuth DPoP according to RFC 9449 first; defer mutual TLS. DPoP provides
sender-constrained token depth for client agents without adding a service mesh,
certificate authority, and certificate lifecycle.

The client generates an ES256 proof key per agent session by default, holds the
private key in process memory, and exposes an encrypted persistence hook when a
session must survive restart. It sends `dpop_jkt` where supported and validates
that the token contains matching `cnf.jkt`.

Proof generation binds `jti`, `htm`, normalized `htu`, `iat`, public JWK, and
`ath` when using an access token. Validation checks signature, method/URI, clock
window, token hash, thumbprint, and single use of `jti`. Redis stores replay IDs
for at least the accepted proof window. Provider nonces are supported when
advertised.

A request is high sensitivity when:

- its requested/effective scope matches `proof_required_scopes`;
- route policy classifies it as write, delete, administration, payment,
  identity, token, credential, or secret management; or
- the application labels it `sensitivity: high`.

These requests require a DPoP-bound token and valid proof. Missing provider
capability, binding, proof, or replay-store availability fails closed; there is no
bearer fallback. Explicit policy may allow bearer tokens for lower-sensitivity
reads. The Kubernetes broker instead uses the bound ServiceAccount tokens in
ADR-001.

## 8. ADR-006 — Minimal encrypted refresh-token custody

Refresh-token persistence is opt-in through `TokenVault`. The production
reference is `EncryptedRedisTokenVault`, reusing Redis required for
revocation/replay. The local in-memory adapter is rejected by production
configuration validation.

After code exchange, AgentShield gives the application an opaque random session
handle and vaults the refresh token. A record contains:

- the SHA-256 digest of the 256-bit session handle as lookup key;
- issuer, subject fingerprint, client/audience, scopes, family ID, version,
  timestamps, expiry, and status;
- the refresh token encrypted with AES-256-GCM using a fresh DEK and nonce;
- the DEK wrapped by the configured KMS; and
- a previous-token fingerprint/tombstone for reuse detection, never the previous
  plaintext token.

Refresh is compare-and-swap. One caller consumes a record version; when the
provider rotates the token, AgentShield encrypts the replacement and atomically
advances it. Reuse of a consumed version marks the family compromised, blocks
further refresh, revokes upstream when supported, and requires reauthentication.
For a non-rotating provider, the vault still serializes refresh and keeps only the
current encrypted value.

Vault TTL never exceeds provider expiry or configured session lifetime. Logout
revokes upstream when possible, retains a short-lived replay tombstone, and
deletes encrypted material. KMS or Redis failure fails closed.

Logs may contain a request ID, truncated fingerprint, issuer ID, decision/reason,
and timings. They redact access/refresh tokens, codes, cookies, private DPoP JWK
values, personal claims, Redis payloads, and KMS material. Canary tests fail if
any artifact contains protected values.

## 9. Core interfaces

```python
class IdentityConnector(Protocol):
    async def authorization_url(self, request: AuthorizationRequest) -> URL: ...
    async def exchange_code(self, request: CodeExchangeRequest) -> Session: ...
    async def refresh(self, session_id: SessionId) -> Session: ...
    async def revoke(self, session_id: SessionId) -> None: ...
    async def exchange_token(self, request: TokenExchangeRequest) -> TokenSet: ...

class TokenValidator(Protocol):
    async def validate(self, token: str, policy: ValidationPolicy) -> TokenClaims: ...

class TokenVault(Protocol):
    async def create(self, token_set: TokenSet, context: SessionContext) -> SessionId: ...
    async def consume_for_refresh(self, session_id: SessionId) -> RefreshLease: ...
    async def commit_rotation(self, lease: RefreshLease, token_set: TokenSet) -> None: ...
    async def compromise_family(self, family_id: str, reason: str) -> None: ...
    async def delete(self, session_id: SessionId) -> None: ...

class KMSProvider(Protocol):
    async def wrap_key(self, plaintext_dek: bytes, context: bytes) -> bytes: ...
    async def unwrap_key(self, wrapped_dek: bytes, context: bytes) -> bytes: ...

class DelegationPolicy(Protocol):
    def authorize_request(self, subject: TokenClaims, request: TokenExchangeRequest) -> None: ...
    async def validate_result(self, subject: TokenClaims, result: TokenSet) -> TokenClaims: ...
```

## 10. ADR-007 — Temporal coordinates durable secret rotation

### Decision

Use Temporal only for long-running, cross-system secret lifecycle operations.
The first workflow is `RotateAgentSecret`; it does not replace Kubernetes
reconciliation, KMS, the broker, or request-path token validation.

The workflow carries only opaque resource references, generation numbers,
policy identifiers, idempotency keys, ciphertext-envelope references, ciphertext
digests, and opaque verification receipts. Temporal persists workflow inputs, activity inputs/results, events,
memo, search attributes, and failures in history. Therefore plaintext secrets,
OAuth tokens, private keys, authorization headers, and unredacted provider
errors are forbidden from every Temporal payload and exception.

The workflow is:

1. wait for a schedule or receive an explicit rotation request;
2. reserve the next generation using an idempotency key;
3. ask a provider activity to create or rotate the credential, returning only
   an opaque one-use credential reference;
4. ask an envelope activity to redeem that reference inside the worker, encrypt
   the value with a fresh DEK, wrap the DEK with KMS, publish ciphertext, clear
   replaceable buffers, and return only the envelope generation and a digest of
   the ciphertext envelope (never a digest of plaintext);
5. ask a verification activity to compare the delivered value inside the
   activity and return only an opaque verification receipt;
6. promote the generation and revoke the previous provider credential; and
7. emit a redacted terminal audit event.

Activities must be idempotent at their external boundary. Retry policies are
bounded and distinguish transient failures from policy, authentication, and
cryptographic failures. Provider creation records a recoverable opaque handle
before returning. If verification fails, compensation disables the candidate
credential and preserves the previous active generation. If promotion succeeds
but old-credential revocation is unavailable, the workflow remains visibly
incomplete and retries revocation; it must not report full success.

Temporal workflow code must be deterministic. Network, clock, randomness, KMS,
Kubernetes, and provider operations occur only in activities. Workflow and
activity versioning must support replay of histories produced by the previous
deployed worker version.

The prototype uses the Temporal Python SDK and deterministic fake provider/KMS
activities in OCI tests. Acceptance evidence must show retry, restart/replay,
compensation, idempotency, and a history scan proving a generated canary does not
occur. Temporal Cloud or a production Temporal cluster is not required.

### Security and operational boundary

- The worker has a dedicated identity with only the specific provider, KMS
  encrypt, and ciphertext-write permissions required by its activities.
- The workflow never receives KMS plaintext output or broker-delivered values.
- A payload codec may add defense in depth, but does not justify putting
  plaintext in history.
- Temporal does not orchestrate per-request JWT validation, DPoP validation, or
  broker authorization because those are latency-sensitive fail-closed paths.
- Temporal does not replace the Kopf controller's convergence semantics.
- Infrastructure provisioning and teardown are outside this workflow. In
  particular, it cannot create GCP resources without the separately documented
  human approval boundary.

### Production-hardening backlog

Production adoption requires authenticated TLS between clients/workers and the
Temporal service, namespace isolation, worker workload identity, payload-codec
key management, HA and disaster recovery, retention and history-size policy,
worker build IDs and replay gates, activity heartbeats, alerting, rate limits,
and tested operator procedures for stuck or partially compensated workflows.

## 11. Security invariants

- Unverified claims never influence key selection, network destinations,
  authorization, logging identity, or cache partitioning.
- Delegated scope is intersection-only, audience/resource is allowlisted, and
  token exchange cannot extend effective lifetime.
- Authorization defaults to deny. Unavailable TokenReview, KMS, Redis replay
  state, or mandatory JWKS data fails closed for the protected operation.
- No real secret/token is test data. Canary values prove redaction; public
  evidence is scanned before publication.
- External calls use TLS verification, strict destinations, deadlines, response
  limits, bounded retries with jitter, and overload protection.
- Production profiles reject development KMS, issuer, token-vault, and TLS modes.
- Audit events record allow/deny reason codes without sensitive values.
- Durable-workflow histories contain references and digests only, never secret
  plaintext or bearer credentials.

## 12. Implementation slices and acceptance tests

1. **Foundation:** typed models, errors, configuration profiles, redaction, audit
   schema, local test issuer, and CI/security tooling.
2. **OIDC session:** PKCE/state/nonce, code exchange, JWT/JWKS validation,
   encrypted vault, rotation/reuse, revocation, and Google OIDC.
3. **DPoP:** proof generation/validation, replay cache, provider nonce, and
   high-sensitivity enforcement.
4. **Delegation:** RFC 8693 client, pre/post policy, provider capabilities, and
   hash-chained audit records with an optional immutable sink.
5. **Secrets:** CRD/envelope, GCP KMS, reconciler, broker, TokenReview/pod policy,
   sidecar/tmpfs delivery, rotation, and cleanup.
6. **Durable rotation:** optional Temporal workflow, idempotent fake activities,
   retry/compensation/replay tests, and history canary scan on OCI.
7. **Evidence:** kind on OCI, then approved GKE Workload
   Identity/KMS validation, priced evidence, and teardown.

Negative tests cover algorithm confusion, issuer/audience mismatch,
unknown/duplicate `kid`, malicious discovery URLs, stale JWKS, state/nonce/PKCE
failure, DPoP replay and URI/method mismatch, refresh concurrency/reuse, token
exchange escalation, cross-namespace access, token audience failure, pod
UID/selector mismatch, ciphertext/AAD tampering, KMS denial/outage, interrupted
rotation, broker overload, and pod deletion cleanup.

## 13. Deferred work

- AgentShield-owned authorization server or token issuer;
- mTLS-bound OAuth tokens;
- CSI driver and automatic admission injection;
- field-level secret ACLs;
- production AWS KMS, Azure Key Vault, and Vault adapters beyond interfaces and
  contract tests;
- multi-cluster high availability and formal compliance certification.
- production Temporal service operation and automated infrastructure lifecycle.

The initial README, packages, diagrams, and blog must not imply deferred
capabilities are implemented.
