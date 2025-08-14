#!/bin/bash
set -euo pipefail

OUT="${1:?Usage: $(basename "$0") <output-dir>}"
rm -rf -- "$OUT"
mkdir -p $OUT

docker buildx build \
  --no-cache \
  --progress=plain \
  --build-context local-package=/workspaces/ossprey-python-client \
  --target sbom-export \
  --output type=local,dest="${OUT}" \
  . # >"${OUT}/build.log" 2>&1

echo "SBOM -> ${OUT}/sbom.json"
