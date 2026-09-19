#!/usr/bin/env bash
set -Eeuo pipefail

readonly PROJECT="redacted-gcp-project"
readonly REGION="northamerica-northeast1"
readonly ZONE="northamerica-northeast1-a"
readonly CLUSTER="agentshield-evidence-r2"
readonly REPOSITORY="agentshield-evidence-r2"
readonly KEYRING="agentshield-evidence"
readonly KEY="envelope"
readonly KEY_REF="projects/${PROJECT}/locations/${REGION}/keyRings/${KEYRING}/cryptoKeys/${KEY}"
readonly RELEASE="evidence"
readonly SYSTEM_NAMESPACE="agentshield-system"
readonly AGENT_NAMESPACE="agents"
readonly IMAGE_TAG="gcp-r2"
readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly EVIDENCE_DIR="${ROOT_DIR}/docs/evidence/gcp-r2"
readonly RUN_DIR="$(mktemp -d /tmp/agentshield-gcp-r2.XXXXXX)"
readonly KUBECTL_BIN="${KUBECTL_BIN:-/tmp/agentshield-tools/kubectl}"
readonly HELM_BIN="${HELM_BIN:-/tmp/agentshield-tools/helm}"

mutated=false
cleanup_started=false

capture_diagnostics() {
  mkdir -p "$EVIDENCE_DIR"
  "$KUBECTL_BIN" get pods,deployments,jobs -A -o wide \
    >"${EVIDENCE_DIR}/workloads.txt" 2>&1 || true
  "$KUBECTL_BIN" get events -A --sort-by=.lastTimestamp \
    >"${EVIDENCE_DIR}/events.txt" 2>&1 || true
  "$KUBECTL_BIN" --namespace "$SYSTEM_NAMESPACE" describe pods \
    >"${EVIDENCE_DIR}/pod-describe.txt" 2>&1 || true
  "$KUBECTL_BIN" --namespace "$SYSTEM_NAMESPACE" logs \
    deployment/evidence-agentshield-broker --all-containers --tail=200 \
    >"${EVIDENCE_DIR}/broker.log" 2>&1 || true
  "$KUBECTL_BIN" --namespace "$SYSTEM_NAMESPACE" logs \
    deployment/evidence-agentshield-operator --all-containers --tail=200 \
    >"${EVIDENCE_DIR}/operator.log" 2>&1 || true
  "$KUBECTL_BIN" --namespace "$AGENT_NAMESPACE" logs \
    --selector=job-name=agentshield-authorized --all-containers --prefix --tail=200 \
    >"${EVIDENCE_DIR}/authorized-all-containers.log" 2>&1 || true
  "$KUBECTL_BIN" --namespace "$AGENT_NAMESPACE" logs \
    --selector=job-name=agentshield-ingest --all-containers --prefix --tail=200 \
    >"${EVIDENCE_DIR}/ingest-all-containers.log" 2>&1 || true
  "$KUBECTL_BIN" --namespace "$AGENT_NAMESPACE" describe pods \
    >"${EVIDENCE_DIR}/agent-pod-describe.txt" 2>&1 || true
}

cleanup() {
  local exit_code=$?
  trap - EXIT INT TERM
  if [[ "$cleanup_started" == "false" ]]; then
    cleanup_started=true
    if [[ -f "${RUN_DIR}/kubeconfig" ]]; then
      capture_diagnostics
    fi
    if [[ "$mutated" == "true" ]]; then
      set +e
      AGENTSHIELD_CONFIRM_PROJECT="$PROJECT" AGENTSHIELD_DISABLE_APIS=true \
        "${ROOT_DIR}/scripts/gcp-teardown.sh" \
        >"${EVIDENCE_DIR}/teardown.log" 2>&1
      teardown_code=$?
      set -e
      if (( teardown_code != 0 )); then
        echo "teardown returned ${teardown_code}; inspect ${EVIDENCE_DIR}/teardown.log" >&2
        if (( exit_code == 0 )); then
          exit_code=$teardown_code
        fi
      fi
    fi
  fi
  find "$RUN_DIR" -type f -exec shred -u {} \; 2>/dev/null || true
  rmdir "$RUN_DIR" 2>/dev/null || true
  exit "$exit_code"
}
trap cleanup EXIT INT TERM

if [[ "${AGENTSHIELD_GCP_APPROVAL:-}" != "approved-r2-lifecycle" ]]; then
  echo "Refusing mutation. Set AGENTSHIELD_GCP_APPROVAL=approved-r2-lifecycle." >&2
  exit 2
fi

mkdir -p "$EVIDENCE_DIR"
export CLOUDSDK_CORE_PROJECT="$PROJECT"
export KUBECONFIG="${RUN_DIR}/kubeconfig"
export PATH="/tmp/agentshield-gke-auth/bin:${PATH}"

if gcloud container clusters describe "$CLUSTER" --zone="$ZONE" \
  --project="$PROJECT" >/dev/null 2>&1; then
  echo "Refusing to reuse existing cluster ${CLUSTER}." >&2
  exit 2
fi
if gcloud artifacts repositories describe "$REPOSITORY" --location="$REGION" \
  --project="$PROJECT" >/dev/null 2>&1; then
  echo "Refusing to reuse existing repository ${REPOSITORY}." >&2
  exit 2
fi

date -u '+%Y-%m-%dT%H:%M:%SZ' >"${EVIDENCE_DIR}/started-at.txt"
mutated=true
gcloud services enable cloudkms.googleapis.com container.googleapis.com \
  --project="$PROJECT"

kms_ready=false
for _attempt in $(seq 1 12); do
  version_state="$(gcloud kms keys versions describe 1 --key="$KEY" \
    --keyring="$KEYRING" --location="$REGION" --project="$PROJECT" \
    --format='value(state)' 2>/dev/null || true)"
  case "$version_state" in
    ENABLED)
      kms_ready=true
      break
      ;;
    DESTROY_SCHEDULED)
      gcloud kms keys versions restore 1 --key="$KEY" --keyring="$KEYRING" \
        --location="$REGION" --project="$PROJECT" --quiet || true
      ;;
    DISABLED)
      if gcloud kms keys versions enable 1 --key="$KEY" --keyring="$KEYRING" \
        --location="$REGION" --project="$PROJECT" --quiet; then
        kms_ready=true
        break
      fi
      ;;
  esac
  sleep 5
done
if [[ "$kms_ready" != "true" ]]; then
  echo "Cloud KMS did not become ready within 60 seconds." >&2
  exit 1
fi

gcloud artifacts repositories create "$REPOSITORY" --repository-format=docker \
  --location="$REGION" --project="$PROJECT" \
  --labels=project=agentshield,purpose=blog-evidence,owner=tanvir,expires=20260919

for name in agentshield-gke-node agentshield-broker agentshield-ingest; do
  gcloud iam service-accounts create "$name" --project="$PROJECT" \
    --display-name="AgentShield evidence ${name}"
done

# IAM service-account creation is eventually consistent across policy APIs.
sleep 20

node_sa="agentshield-gke-node@${PROJECT}.iam.gserviceaccount.com"
broker_sa="agentshield-broker@${PROJECT}.iam.gserviceaccount.com"
ingest_sa="agentshield-ingest@${PROJECT}.iam.gserviceaccount.com"
gcloud projects add-iam-policy-binding "$PROJECT" --member="serviceAccount:${node_sa}" \
  --role=roles/container.defaultNodeServiceAccount --quiet
gcloud projects add-iam-policy-binding "$PROJECT" --member="serviceAccount:${node_sa}" \
  --role=roles/artifactregistry.reader --quiet
gcloud kms keys add-iam-policy-binding "$KEY" --keyring="$KEYRING" --location="$REGION" \
  --project="$PROJECT" --member="serviceAccount:${broker_sa}" \
  --role=roles/cloudkms.cryptoKeyDecrypter --quiet
gcloud kms keys add-iam-policy-binding "$KEY" --keyring="$KEYRING" --location="$REGION" \
  --project="$PROJECT" --member="serviceAccount:${ingest_sa}" \
  --role=roles/cloudkms.cryptoKeyEncrypter --quiet
gcloud iam service-accounts add-iam-policy-binding "$broker_sa" --project="$PROJECT" \
  --member="serviceAccount:${PROJECT}.svc.id.goog[${SYSTEM_NAMESPACE}/evidence-agentshield-broker]" \
  --role=roles/iam.workloadIdentityUser --quiet
gcloud iam service-accounts add-iam-policy-binding "$ingest_sa" --project="$PROJECT" \
  --member="serviceAccount:${PROJECT}.svc.id.goog[${AGENT_NAMESPACE}/agentshield-ingest]" \
  --role=roles/iam.workloadIdentityUser --quiet

project_number="$(gcloud projects describe "$PROJECT" --format='value(projectNumber)')"
source_bucket="gs://agentshield-evidence-source-${project_number}"
gcloud storage buckets create "$source_bucket" --project="$PROJECT" \
  --location="$REGION" --uniform-bucket-level-access

image_repository="${REGION}-docker.pkg.dev/${PROJECT}/${REPOSITORY}/agentshield"
gcloud builds submit "$ROOT_DIR" --project="$PROJECT" --tag="${image_repository}:${IMAGE_TAG}" \
  --gcs-source-staging-dir="${source_bucket}/source" --timeout=10m
image_digest="$(gcloud artifacts docker images list "$image_repository" --include-tags \
  --filter="tags:${IMAGE_TAG}" --format='value(version)' --limit=1 --project="$PROJECT")"
if [[ "$image_digest" != sha256:* ]]; then
  echo "Could not resolve the built image digest." >&2
  exit 1
fi
readonly IMAGE_REFERENCE="${image_repository}@${image_digest}"
printf '%s\n' "$IMAGE_REFERENCE" >"${EVIDENCE_DIR}/image-reference.txt"

gcloud container clusters create "$CLUSTER" --project="$PROJECT" --zone="$ZONE" \
  --machine-type=e2-medium --num-nodes=1 --disk-type=pd-balanced --disk-size=20 \
  --service-account="$node_sa" --scopes=cloud-platform \
  --workload-pool="${PROJECT}.svc.id.goog" --enable-ip-alias --enable-network-policy \
  --logging=NONE --monitoring=NONE --no-enable-managed-prometheus \
  --metadata=disable-legacy-endpoints=true --enable-shielded-nodes \
  --labels=project=agentshield,purpose=blog-evidence,owner=tanvir,expires=20260919
gcloud container clusters get-credentials "$CLUSTER" --project="$PROJECT" --zone="$ZONE"

# GKE can report RUNNING before its node network dataplane is ready. Do not
# launch evidence workloads until both the node and Calico daemon are healthy.
"$KUBECTL_BIN" wait --for=condition=Ready nodes --all --timeout=240s
"$KUBECTL_BIN" --namespace kube-system rollout status daemonset/calico-node \
  --timeout=240s

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj "/CN=evidence-agentshield-broker.${SYSTEM_NAMESPACE}.svc" \
  -addext "subjectAltName=DNS:evidence-agentshield-broker.${SYSTEM_NAMESPACE}.svc,DNS:evidence-agentshield-broker.${SYSTEM_NAMESPACE}.svc.cluster.local" \
  -keyout "${RUN_DIR}/tls.key" -out "${RUN_DIR}/tls.crt" >/dev/null 2>&1

"$KUBECTL_BIN" create namespace "$SYSTEM_NAMESPACE"
"$KUBECTL_BIN" create namespace "$AGENT_NAMESPACE"
"$KUBECTL_BIN" label namespace "$AGENT_NAMESPACE" agentshield.io/secret-access=true
"$KUBECTL_BIN" --namespace "$SYSTEM_NAMESPACE" create secret tls broker-tls \
  --cert="${RUN_DIR}/tls.crt" --key="${RUN_DIR}/tls.key"
"$KUBECTL_BIN" --namespace "$AGENT_NAMESPACE" create configmap agentshield-broker-ca \
  --from-file="ca.crt=${RUN_DIR}/tls.crt"

"$HELM_BIN" install "$RELEASE" "${ROOT_DIR}/helm/agentshield" \
  --namespace "$SYSTEM_NAMESPACE" --set image.repository="$image_repository" \
  --set image.digest="$image_digest" --set tls.secretName=broker-tls \
  --set gcp.kmsKeyRef="$KEY_REF" --set gcp.serviceAccount="$broker_sa" \
  --set targetNamespace="$AGENT_NAMESPACE"

if ! "$KUBECTL_BIN" --namespace "$SYSTEM_NAMESPACE" rollout status \
  deployment/evidence-agentshield-broker --timeout=180s; then
  capture_diagnostics
  exit 1
fi
if ! "$KUBECTL_BIN" --namespace "$SYSTEM_NAMESPACE" rollout status \
  deployment/evidence-agentshield-operator --timeout=180s; then
  capture_diagnostics
  exit 1
fi

"$KUBECTL_BIN" apply -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: agentshield-ingest
  namespace: ${AGENT_NAMESPACE}
  annotations:
    iam.gke.io/gcp-service-account: ${ingest_sa}
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: agent-runner
  namespace: ${AGENT_NAMESPACE}
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: unauthorized-agent
  namespace: ${AGENT_NAMESPACE}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: agentshield-ingest
  namespace: ${AGENT_NAMESPACE}
rules:
  - apiGroups: ["agentshield.io"]
    resources: ["agentsecrets"]
    verbs: ["get"]
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "create", "update"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: agentshield-ingest
  namespace: ${AGENT_NAMESPACE}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: agentshield-ingest
subjects:
  - kind: ServiceAccount
    name: agentshield-ingest
    namespace: ${AGENT_NAMESPACE}
---
apiVersion: agentshield.io/v1alpha1
kind: AgentSecret
metadata:
  name: llm-key
  namespace: ${AGENT_NAMESPACE}
spec:
  secretType: APIKey
  rotation:
    enabled: true
    intervalHours: 24
    notifyOnRotation: true
  encryption:
    provider: gcp-kms
    keyRef: ${KEY_REF}
  access:
    allowedServiceAccounts:
      - name: agent-runner
        namespace: ${AGENT_NAMESPACE}
    scopedTo:
      matchLabels:
        app: authorized-agent
---
apiVersion: batch/v1
kind: Job
metadata:
  name: agentshield-ingest
  namespace: ${AGENT_NAMESPACE}
spec:
  backoffLimit: 1
  template:
    spec:
      restartPolicy: Never
      serviceAccountName: agentshield-ingest
      containers:
        - name: ingest
          image: ${IMAGE_REFERENCE}
          imagePullPolicy: IfNotPresent
          command: ["python", "-c"]
          args:
            - |
              import asyncio, hashlib, secrets
              from agentshield.secrets.cli import _put
              value = bytearray(b"agentshield-gke-r2-" + secrets.token_bytes(32))
              try:
                  print("EXPECTED_SHA256=" + hashlib.sha256(value).hexdigest())
                  generation = asyncio.run(_put("agents", "llm-key", "${KEY_REF}", bytes(value), None))
                  print("GENERATION=" + str(generation))
              finally:
                  value[:] = b"\\x00" * len(value)
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
EOF

"$KUBECTL_BIN" --namespace "$AGENT_NAMESPACE" wait --for=condition=complete \
  job/agentshield-ingest --timeout=360s
"$KUBECTL_BIN" --namespace "$AGENT_NAMESPACE" logs job/agentshield-ingest \
  >"${EVIDENCE_DIR}/ingest.log"
expected_digest="$(sed -n 's/^EXPECTED_SHA256=//p' "${EVIDENCE_DIR}/ingest.log")"
if [[ ! "$expected_digest" =~ ^[0-9a-f]{64}$ ]]; then
  echo "Ingest did not produce a valid canary digest." >&2
  exit 1
fi
"$KUBECTL_BIN" --namespace "$AGENT_NAMESPACE" create configmap agentshield-expected \
  --from-literal="sha256=${expected_digest}"

sed -e "s|agentshield:local|${IMAGE_REFERENCE}|g" \
  -e 's|imagePullPolicy: Never|imagePullPolicy: IfNotPresent|g' \
  -e 's|test-agentshield-broker|evidence-agentshield-broker|g' \
  "${ROOT_DIR}/tests/integration/kind-jobs.yaml" | "$KUBECTL_BIN" apply -f -
"$KUBECTL_BIN" --namespace "$AGENT_NAMESPACE" wait --for=condition=complete \
  job/agentshield-authorized job/agentshield-denied --timeout=240s
"$KUBECTL_BIN" --namespace "$AGENT_NAMESPACE" logs job/agentshield-authorized -c verifier \
  >"${EVIDENCE_DIR}/authorized.log"
"$KUBECTL_BIN" --namespace "$AGENT_NAMESPACE" logs job/agentshield-denied -c probe \
  >"${EVIDENCE_DIR}/denied.log"

if ! rg -q 'secret delivery verified' "${EVIDENCE_DIR}/authorized.log"; then
  echo "Authorized delivery evidence missing." >&2
  exit 1
fi
if ! rg -q 'unauthorized request denied with HTTP 403' "${EVIDENCE_DIR}/denied.log"; then
  echo "Unauthorized denial evidence missing." >&2
  exit 1
fi
if rg -l 'agentshield-gke-r2-' "$EVIDENCE_DIR" >/dev/null; then
  echo "Plaintext canary marker found in retained evidence." >&2
  exit 1
fi

capture_diagnostics
gcloud logging read \
  'protoPayload.serviceName="cloudkms.googleapis.com" AND resource.labels.crypto_key_id="envelope"' \
  --project="$PROJECT" --freshness=2h --limit=50 --format=json \
  >"${EVIDENCE_DIR}/kms-audit.json" || true
date -u '+%Y-%m-%dT%H:%M:%SZ' >"${EVIDENCE_DIR}/finished-at.txt"
echo "GKE/KMS evidence passed; teardown will run now."
