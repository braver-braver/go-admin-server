#!/usr/bin/env bash
# Copies the generated OpenAPI document from a react-admin-starter checkout
# (or a GitHub ref) into api/openapi.yaml and validates it.
#
#   scripts/sync-contract.sh ../react-admin-starter      # local checkout
#   scripts/sync-contract.sh v1.0.0                      # tag or commit on GitHub
#
# Never edit api/openapi.yaml by hand: change the frontend's src/contract,
# run `pnpm openapi` there, then sync.
set -euo pipefail
cd "$(dirname "$0")/.."
src="${1:?path to a react-admin-starter checkout, or a git ref}"
if [[ -d "$src" ]]; then
  (cd "$src" && pnpm -s openapi:check)
  cp "$src/docs/api.openapi.yaml" api/openapi.yaml
else
  curl -fsSL "https://raw.githubusercontent.com/braver-braver/react-admin-starter/$src/docs/api.openapi.yaml" -o api/openapi.yaml
fi
go run ./tools/oacheck api/openapi.yaml
