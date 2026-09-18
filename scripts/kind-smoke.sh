#!/usr/bin/env bash
set -euo pipefail

KIND_BIN="${KIND_BIN:-kind}"
KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"
HELM_BIN="${HELM_BIN:-helm}"
CLUSTER_NAME="${CLUSTER_NAME:-agentshield-evidence}"
NODE_IMAGE="kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"
SYSTEM_NAMESPACE="agentshield-system"
KMS_KEY_B64="a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s="
KMS_KEY_REF="projects/test/locations/global/keyRings/test/cryptoKeys/test"
WORK_DIR="$(mktemp -d /tmp/agentshield-kind.XXXXXX)"

cleanup() {
  "$KIND_BIN" delete cluster --name "$CLUSTER_NAME"
  find "$WORK_DIR" -type f -exec shred -u {} \; 2>/dev/null || true
  rmdir "$WORK_DIR" 2>/dev/null || true
}
trap cleanup EXIT

"$KIND_BIN" create cluster --name "$CLUSTER_NAME" --image "$NODE_IMAGE" --wait 120s
docker build -t agentshield:local .
"$KIND_BIN" load docker-image agentshield:local --name "$CLUSTER_NAME"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj "/CN=test-agentshield-broker.agentshield-system.svc" \
  -addext "subjectAltName=DNS:test-agentshield-broker.agentshield-system.svc,DNS:test-agentshield-broker.agentshield-system.svc.cluster.local" \
  -keyout "$WORK_DIR/tls.key" -out "$WORK_DIR/tls.crt" >/dev/null 2>&1

"$KUBECTL_BIN" create namespace "$SYSTEM_NAMESPACE"
"$KUBECTL_BIN" --namespace "$SYSTEM_NAMESPACE" create secret tls broker-tls \
  --cert "$WORK_DIR/tls.crt" --key "$WORK_DIR/tls.key"
"$KUBECTL_BIN" --namespace "$SYSTEM_NAMESPACE" create secret generic fake-kms \
  --from-literal "key=$KMS_KEY_B64"

"$HELM_BIN" install test helm/agentshield --namespace "$SYSTEM_NAMESPACE" \
  --set image.repository=agentshield \
  --set image.tag=local \
  --set image.pullPolicy=Never \
  --set tls.secretName=broker-tls \
  --set "gcp.kmsKeyRef=$KMS_KEY_REF" \
  --set runtime.environment=test \
  --set runtime.kmsProvider=fake \
  --set runtime.fakeKmsSecretName=fake-kms

"$KUBECTL_BIN" apply -f tests/integration/kind-prereqs.yaml
"$KUBECTL_BIN" --namespace agents create configmap agentshield-broker-ca \
  --from-file "ca.crt=$WORK_DIR/tls.crt"

.venv/bin/python tests/integration/generate_kind_envelope.py \
  --output "$WORK_DIR/envelope.json" \
  --digest-output "$WORK_DIR/sha256" \
  --key-b64 "$KMS_KEY_B64" \
  --key-ref "$KMS_KEY_REF"

"$KUBECTL_BIN" --namespace agents create secret generic \
  agentshield-envelope-llm-key-513242da0b \
  --from-file "envelope.json=$WORK_DIR/envelope.json"
"$KUBECTL_BIN" --namespace agents annotate secret \
  agentshield-envelope-llm-key-513242da0b agentshield.io/generation=1
"$KUBECTL_BIN" --namespace agents create configmap agentshield-expected \
  --from-file "sha256=$WORK_DIR/sha256"

"$KUBECTL_BIN" --namespace "$SYSTEM_NAMESPACE" rollout status \
  deployment/test-agentshield-broker --timeout=120s
"$KUBECTL_BIN" --namespace "$SYSTEM_NAMESPACE" rollout status \
  deployment/test-agentshield-operator --timeout=120s
"$KUBECTL_BIN" apply -f tests/integration/kind-jobs.yaml
"$KUBECTL_BIN" --namespace agents wait --for=condition=complete \
  job/agentshield-authorized job/agentshield-denied --timeout=120s
"$KUBECTL_BIN" --namespace agents logs job/agentshield-authorized -c verifier
"$KUBECTL_BIN" --namespace agents logs job/agentshield-denied -c probe
"$KUBECTL_BIN" --namespace "$SYSTEM_NAMESPACE" logs \
  deployment/test-agentshield-broker --tail=50
