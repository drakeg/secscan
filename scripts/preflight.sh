#!/usr/bin/env bash
set -euo pipefail

run_container=false
if [[ "${1:-}" == "--container" ]]; then
  run_container=true
elif [[ $# -gt 0 ]]; then
  echo "usage: scripts/preflight.sh [--container]" >&2
  exit 2
fi

rm -rf dist /tmp/secscan-wheel-test

ruff check .
mypy
pytest
python -m build --wheel
python scripts/verify_wheel.py dist/secscan-*.whl

python -m venv /tmp/secscan-wheel-test
/tmp/secscan-wheel-test/bin/pip install dist/secscan-*.whl
/tmp/secscan-wheel-test/bin/python -c "import secscan, secscan.aws, secscan.cli, secscan.compare, secscan.history, secscan.models, secscan.normalize, secscan.policy, secscan.report, secscan.service, secscan.service_cli, secscan.trivy, secscan.scanners, secscan.scanners.base, secscan.scanners.registry, secscan.scanners.image, secscan.scanners.filesystem, secscan.scanners.repository, secscan.scanners.sbom"
/tmp/secscan-wheel-test/bin/secscan --version
/tmp/secscan-wheel-test/bin/secscan-service --help >/dev/null

if [[ "$run_container" == true ]]; then
  docker build --no-cache --progress=plain -t secscan:preflight .
  docker run --rm secscan:preflight --version
  docker run --rm --entrypoint secscan-service secscan:preflight --help >/dev/null
  docker save secscan:preflight --output /tmp/secscan-preflight.tar
  mkdir -p /tmp/trivy-cache
  docker run --rm \
    -v /tmp/secscan-preflight.tar:/scan/secscan-preflight.tar:ro \
    -v /tmp/trivy-cache:/root/.cache/ \
    aquasec/trivy:0.72.0 image \
    --input /scan/secscan-preflight.tar \
    --exit-code 1 \
    --ignore-unfixed \
    --severity CRITICAL
fi

echo "secscan preflight passed"
