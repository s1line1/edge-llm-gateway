#!/usr/bin/env bash
# Create one on-demand credential pair for local make dev and write an agent config.
# The gateway itself starts with zero credentials; this script performs the admin API call.
set -euo pipefail

base="${1:-http://127.0.0.1:8080}"
out="${2:-.tmp/dev-client}"
admin_token="${DEV_ADMIN_TOKEN:-dev-admin}"

mkdir -p "$out" .tmp
name="dev-$(date +%s)"
server_name="${name}.localhost"

created="$(curl -fsS \
  -H "Authorization: Bearer ${admin_token}" \
  -H 'Content-Type: application/json' \
  -X POST "${base}/admin/pki/pairs" \
  --data "{\"name\":\"${name}\",\"tenant_id\":\"default\",\"server_name\":\"${server_name}\"}")"

id="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' <<<"$created")"

curl -fsS \
  -H "Authorization: Bearer ${admin_token}" \
  "${base}/admin/pki/pairs/${id}/download" \
  -o ".tmp/dev-client.tar"

rm -rf "$out"
mkdir -p "$out"
tar -xf .tmp/dev-client.tar -C "$out"

cat > .tmp/agent-config.dev.yml <<YAML
cloud_addr: "127.0.0.1:4433"
server_name: "${server_name}"
ca: "${out}/ca.crt"
cert: "${out}/client.crt"
key: "${out}/client.key"
agent_id: "edge-1"
upstream: "http://127.0.0.1:11435"
max_concurrency: 4
request_log: true
models:
  - qwen2.5
YAML

echo "created ${name} (${server_name}); agent config: .tmp/agent-config.dev.yml"
