#!/usr/bin/env bash
set -uo pipefail

# Idempotent teardown for the dedicated AgentShield evidence environment.
# This script intentionally uses exact resource names and project flags. It may
# be rerun after partial failure. It never deletes unrelated project resources.

readonly PROJECT="redacted-gcp-project"
readonly REGION="northamerica-northeast1"
readonly ZONE="northamerica-northeast1-a"
readonly CLUSTER="agentshield-evidence"
readonly REPOSITORY="agentshield-evidence"
readonly KEYRING="agentshield-evidence"
readonly KEY="envelope"
readonly SOURCE_BUCKET_PREFIX="gs://agentshield-evidence-source-"
readonly SERVICE_ACCOUNTS=(
  "agentshield-gke-node@${PROJECT}.iam.gserviceaccount.com"
  "agentshield-broker@${PROJECT}.iam.gserviceaccount.com"
  "agentshield-ingest@${PROJECT}.iam.gserviceaccount.com"
)

failures=0

run_delete() {
  local description="$1"
  shift
  echo "teardown: ${description}"
  if ! "$@"; then
    echo "warning: ${description} did not complete; continuing for idempotent cleanup" >&2
    failures=$((failures + 1))
  fi
}

if [[ "${AGENTSHIELD_CONFIRM_PROJECT:-}" != "$PROJECT" ]]; then
  echo "Refusing teardown. Set AGENTSHIELD_CONFIRM_PROJECT=${PROJECT}." >&2
  exit 2
fi

active_project="$(gcloud config get-value project 2>/dev/null || true)"
if [[ -n "$active_project" && "$active_project" != "(unset)" && "$active_project" != "$PROJECT" ]]; then
  echo "Refusing teardown: active gcloud project is ${active_project}." >&2
  exit 2
fi

if gcloud container clusters describe "$CLUSTER" --zone="$ZONE" \
  --project="$PROJECT" >/dev/null 2>&1; then
  run_delete "GKE cluster" \
    gcloud container clusters delete "$CLUSTER" --zone="$ZONE" --project="$PROJECT" --quiet
else
  echo "already absent: GKE cluster"
fi

if gcloud artifacts repositories describe "$REPOSITORY" --location="$REGION" \
  --project="$PROJECT" >/dev/null 2>&1; then
  run_delete "Artifact Registry repository" \
    gcloud artifacts repositories delete "$REPOSITORY" --location="$REGION" \
      --project="$PROJECT" --quiet
else
  echo "already absent: Artifact Registry repository"
fi

for account in "${SERVICE_ACCOUNTS[@]}"; do
  if gcloud iam service-accounts describe "$account" --project="$PROJECT" >/dev/null 2>&1; then
    case "$account" in
      "agentshield-gke-node@${PROJECT}.iam.gserviceaccount.com")
        gcloud projects remove-iam-policy-binding "$PROJECT" \
          --member="serviceAccount:${account}" \
          --role=roles/container.defaultNodeServiceAccount --quiet >/dev/null 2>&1 || true
        gcloud projects remove-iam-policy-binding "$PROJECT" \
          --member="serviceAccount:${account}" \
          --role=roles/artifactregistry.reader --quiet >/dev/null 2>&1 || true
        ;;
      "agentshield-broker@${PROJECT}.iam.gserviceaccount.com")
        gcloud kms keys remove-iam-policy-binding "$KEY" --keyring="$KEYRING" \
          --location="$REGION" --project="$PROJECT" \
          --member="serviceAccount:${account}" \
          --role=roles/cloudkms.cryptoKeyDecrypter --quiet >/dev/null 2>&1 || true
        gcloud iam service-accounts remove-iam-policy-binding "$account" \
          --project="$PROJECT" \
          --member="serviceAccount:${PROJECT}.svc.id.goog[agentshield-system/agentshield-broker]" \
          --role=roles/iam.workloadIdentityUser --quiet >/dev/null 2>&1 || true
        ;;
      "agentshield-ingest@${PROJECT}.iam.gserviceaccount.com")
        gcloud kms keys remove-iam-policy-binding "$KEY" --keyring="$KEYRING" \
          --location="$REGION" --project="$PROJECT" \
          --member="serviceAccount:${account}" \
          --role=roles/cloudkms.cryptoKeyEncrypter --quiet >/dev/null 2>&1 || true
        gcloud iam service-accounts remove-iam-policy-binding "$account" \
          --project="$PROJECT" \
          --member="serviceAccount:${PROJECT}.svc.id.goog[agents/agentshield-ingest]" \
          --role=roles/iam.workloadIdentityUser --quiet >/dev/null 2>&1 || true
        ;;
    esac
    run_delete "service account ${account}" \
      gcloud iam service-accounts delete "$account" --project="$PROJECT" --quiet
  else
    echo "already absent: service account ${account}"
  fi
done

versions="$(gcloud kms keys versions list \
  --key="$KEY" --keyring="$KEYRING" --location="$REGION" --project="$PROJECT" \
  --filter='state!=DESTROYED AND state!=DESTROY_SCHEDULED' --format='value(name)' 2>/dev/null || true)"
while IFS= read -r version; do
  [[ -z "$version" ]] && continue
  run_delete "KMS key version ${version}" \
    gcloud kms keys versions destroy "$version" --key="$KEY" --keyring="$KEYRING" \
      --location="$REGION" --project="$PROJECT" --quiet
done <<< "$versions"

project_number="$(gcloud projects describe "$PROJECT" --format='value(projectNumber)' 2>/dev/null || true)"
if [[ -n "$project_number" ]]; then
  source_bucket="${SOURCE_BUCKET_PREFIX}${project_number}"
  if gcloud storage buckets describe "$source_bucket" --project="$PROJECT" >/dev/null 2>&1; then
    run_delete "dedicated Cloud Build source bucket" \
      gcloud storage rm --recursive "$source_bucket"
  else
    echo "already absent: dedicated Cloud Build source bucket"
  fi
fi

if [[ "${AGENTSHIELD_DISABLE_APIS:-false}" == "true" ]]; then
  for api in container.googleapis.com cloudkms.googleapis.com file.googleapis.com networkconnectivity.googleapis.com; do
    run_delete "API ${api}" \
      gcloud services disable "$api" --project="$PROJECT" --quiet
  done
fi

echo "verification: remaining dedicated compute/storage resources"
gcloud container clusters list --project="$PROJECT" --filter="name=${CLUSTER}" \
  --format='table(name,location,status)' 2>/dev/null || true
gcloud compute instances list --project="$PROJECT" \
  --filter="labels.goog-k8s-cluster-name=${CLUSTER}" --format='table(name,zone,status)' 2>/dev/null || true
gcloud compute disks list --project="$PROJECT" \
  --filter="labels.goog-k8s-cluster-name=${CLUSTER}" --format='table(name,zone,status)' 2>/dev/null || true
gcloud compute addresses list --project="$PROJECT" \
  --filter="name~'${CLUSTER}'" --format='table(name,region,status,addressType)' 2>/dev/null || true
gcloud artifacts repositories list --project="$PROJECT" --location="$REGION" \
  --filter="name:${REPOSITORY}" --format='table(name,format)' 2>/dev/null || true
gcloud iam service-accounts list --project="$PROJECT" \
  --filter="email~'^agentshield-(gke-node|broker|ingest)@'" \
  --format='table(email,disabled)' 2>/dev/null || true
gcloud kms keys versions list --key="$KEY" --keyring="$KEYRING" \
  --location="$REGION" --project="$PROJECT" \
  --format='table(name,state,destroyTime)' 2>/dev/null || true
gcloud asset search-all-resources --scope="projects/${PROJECT}" \
  --query="${CLUSTER}" --format='table(assetType,name,state)' 2>/dev/null || true
gcloud services list --enabled --project="$PROJECT" \
  --filter='config.name:(container.googleapis.com OR cloudkms.googleapis.com OR file.googleapis.com OR networkconnectivity.googleapis.com)' \
  --format='table(config.name)' 2>/dev/null || true

if (( failures > 0 )); then
  echo "Teardown completed with ${failures} warning(s); inspect the verification output." >&2
  exit 1
fi
echo "Teardown commands completed; manual billing and Cloud Asset verification remain required."
