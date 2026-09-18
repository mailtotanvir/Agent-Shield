# AgentShield STRIDE Threat Model

Status: initial implementation baseline  
Date: 2026-09-18

## Scope and assets

Protected assets are OAuth authorization codes, access/refresh tokens, DPoP
private keys, plaintext agent secrets, envelope DEKs, authorization policy,
audit integrity, and the availability of authentication and secret delivery.

Trust boundaries exist at the browser-to-agent redirect, agent-to-IdP HTTPS
connection, discovery/JWKS fetch, application-to-Redis connection, pod-to-broker
TLS connection, broker-to-Kubernetes API, broker/CLI-to-KMS connection, and
container-to-node boundary.

Assumed trusted foundations are the configured IdP, Kubernetes control plane,
cloud KMS, TLS roots, container runtime, and cluster administrators. A malicious
cluster administrator or compromised node can inspect pod memory and is outside
the first-release confidentiality guarantee.

## Threat register

| STRIDE | Threat | Primary controls | Required evidence | Residual risk |
|---|---|---|---|---|
| Spoofing | Forged OAuth response or callback | PKCE S256, state, nonce, exact redirect URI, pinned issuer | negative state/nonce/PKCE tests | compromised browser/client host |
| Spoofing | Forged JWT or key confusion | ES256/RS256 allowlist, pinned issuer/audience, reject `jku`/`x5u`, bounded JWKS | algorithm and malicious-header tests | trusted IdP key compromise |
| Spoofing | Pod impersonates an allowed workload | audience-restricted pod-bound token, TokenReview, live pod UID/SA lookup | wrong audience/UID/SA tests | cluster-admin/node compromise |
| Tampering | Ciphertext, nonce, or metadata changed | AES-256-GCM, immutable identity/generation as AAD, KMS-wrapped DEK | bit-flip and AAD mismatch tests | denial of service remains possible |
| Tampering | Delegated authority widened | scope intersection, audience/resource allowlist, post-validation, lifetime cap | escalation and confused-deputy tests | provider-specific claim semantics |
| Repudiation | Actor denies secret/token action | structured allow/deny audit, request IDs, fingerprints, hash chain, immutable sink option | correlated positive/negative traces | local-only logs are admin-rewritable |
| Information disclosure | Tokens/secrets leak through logs | structured allowlist logging, recursive redaction, canary scanning | artifact scan with canaries | Python copies cannot be fully zeroized |
| Information disclosure | Plaintext persists in etcd/disk | client-side ingestion encryption, ciphertext-only Secret, TLS broker, tmpfs delivery | API object dump and node/pod lifecycle checks | privileged node process can read RAM |
| Denial of service | JWKS refresh storm or hostile IdP | coalesced cache refresh, timeouts, size/key-count bounds, no redirects | concurrency/outage tests | IdP outage fails authentication closed |
| Denial of service | Broker/KMS exhaustion | semaphore, request/response bounds, NetworkPolicy, resource limits, backoff | overload and KMS outage tests | authorized tenants can consume quota |
| Elevation | DPoP token replay or bearer downgrade | `cnf.jkt`, method/URI/token hash binding, Redis single-use `jti`, fail closed | replay and downgrade tests | Redis outage blocks sensitive actions |
| Elevation | Refresh-token reuse | encrypted vault, atomic lease, family kill switch, upstream revocation | concurrent/reused lease tests | provider may lack revocation support |
| Elevation | Overprivileged cloud identity | distinct writer/broker identities; encrypt-only vs decrypt-only KMS roles | IAM policy capture and denial tests | KMS role granularity is key-level |

## Security invariants

1. Unverified token material never selects a network destination or key.
2. AgentShield does not issue OAuth tokens in the initial release.
3. Plaintext agent secrets never enter Kubernetes API objects.
4. A workload must pass TokenReview, pod UID/ServiceAccount verification, and
   `AgentSecret` policy before decryption.
5. High-sensitivity OAuth operations require DPoP with working replay storage;
   failure never downgrades to bearer authentication.
6. Refresh token material is either memory-only or KMS-envelope-encrypted.
7. Denials reveal stable reason codes, not tokens, claims, keys, or plaintext.
8. Development cryptography/storage/TLS adapters are rejected in production.

## Abuse cases kept in the regression suite

- algorithm `none`/HS256, invalid signature, duplicate or unknown `kid`, `jku`
  injection, malicious discovery endpoint, wrong issuer/audience, expired/future
  token, missing scope, and JWKS outage;
- DPoP proof replay, wrong key/method/URI/token hash/nonce, stale proof, and
  unavailable replay store;
- token exchange to an unapproved audience/resource, scope union, changed
  subject, longer expiry, and invalid returned token;
- refresh races, stale lease reuse, expired session, corrupted envelope, and KMS
  outage;
- unbound/wrong-audience Kubernetes token, deleted/recreated pod UID, wrong
  ServiceAccount, selector mismatch, cross-namespace request, envelope identity
  mismatch, and ciphertext/AAD tampering; and
- secret canaries in logs, status, events, manifests, command transcripts, and
  public evidence.

## Review triggers

Re-run the threat model before adding an AgentShield issuer, admission webhook,
CSI driver, new KMS provider, cross-namespace secret sharing, persistent DPoP
keys, externally reachable broker, or multi-tenant control plane.

