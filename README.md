# AgentShield

AgentShield is a security toolkit for client agents: strict OAuth/OIDC token
validation, delegated-authority policy, and KMS-backed Kubernetes secret
delivery without storing plaintext in etcd.

The project is under active development. Its accepted initial architecture is in
[design.md](design.md), the build/evidence workflow is in
[IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md), and the broader vision is in
[agentshield-spec.md](agentshield-spec.md).

## Security boundary

AgentShield is an OAuth client and policy layer. It does not issue tokens or act
as an authorization server. External providers own signing keys and issuance.
The Kubernetes secret path uses an authenticated broker and explicit sidecar;
plaintext exists briefly in process memory and a pod-local memory-backed volume,
but never in a Kubernetes API object.

Do not use this development release for production credentials.

