#!/usr/bin/env bash
set -euo pipefail

case "${1:-}" in
  dockerhub)
    : "${DOCKERHUB_USERNAME:?Docker Hub username secret is missing}"
    : "${DOCKERHUB_TOKEN:?Docker Hub token secret is missing}"
    registry=docker.io
    namespace=${DOCKERHUB_USERNAME,,}
    username=$DOCKERHUB_USERNAME
    password=$DOCKERHUB_TOKEN
    ;;
  acr)
    : "${ACR_URL:?ACR URL secret is missing}"
    : "${ACR_USERNAME:?ACR username secret is missing}"
    : "${ACR_PASSWORD:?ACR password secret is missing}"
    # ACR_URL may be a host, host/namespace, or a full image path. Never
    # overwrite the repository component of a URL copied from another project.
    parsed=$(python3 - <<'PY'
import os, re, urllib.parse
raw = os.environ['ACR_URL'].strip().rstrip('/')
u = urllib.parse.urlsplit(raw if '://' in raw else 'https://' + raw)
if (u.scheme != 'https' or not u.hostname or u.username or u.password or
    u.query or u.fragment or u.port is not None or
    not re.fullmatch(r'[a-z0-9][a-z0-9.-]*\.aliyuncs\.com', u.hostname)):
    raise SystemExit('ACR_URL must point to an HTTPS Alibaba Cloud registry')
parts = [p for p in u.path.split('/') if p]
if len(parts) > 2 or any(not re.fullmatch(r'[a-z0-9][a-z0-9_-]*', p) for p in parts):
    raise SystemExit('ACR_URL has an invalid namespace or image path')
namespace = parts[0] if parts else os.environ.get('ACR_NAMESPACE', '')
if not re.fullmatch(r'[a-z0-9][a-z0-9_-]*', namespace):
    raise SystemExit('Provide the ACR namespace in ACR_URL or the workflow input')
print(u.hostname, namespace)
PY
)
    read -r registry namespace <<< "$parsed"
    username=$ACR_USERNAME
    password=$ACR_PASSWORD
    ;;
  *) echo 'Expected registry argument: dockerhub or acr' >&2; exit 2 ;;
esac

[[ "$namespace" =~ ^[a-z0-9][a-z0-9_-]*$ ]]
[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]
source_image="netbox-sync-release:$TAG"
target_image="$registry/$namespace/netbox-sync:$TAG"
expected=$(cat artifact/image-id.txt)
test "$(docker image inspect "$source_image" --format '{{.Id}}')" = "$expected"

DOCKER_CONFIG=$(mktemp -d)
export DOCKER_CONFIG
trap 'docker logout "$registry" >/dev/null 2>&1 || true; rm -f "$DOCKER_CONFIG/config.json"; rmdir "$DOCKER_CONFIG" 2>/dev/null || true' EXIT
printf '%s' "$password" | docker login "$registry" --username "$username" --password-stdin
unset password
docker tag "$source_image" "$target_image"
test "$(docker image inspect "$target_image" --format '{{.Id}}')" = "$expected"
docker push "$target_image"
docker manifest inspect "$target_image" >/dev/null
echo "Published netbox-sync $TAG to $1 from the verified release image."
