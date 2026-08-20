FROM aquasec/trivy:0.74.0 AS trivy

FROM golang:1.25-bookworm AS gitleaks-builder
RUN mkdir -p /out \
    && GOBIN=/out go install github.com/gitleaks/gitleaks/v8@v8.30.1

FROM python:3.14.7-slim-bookworm AS builder
WORKDIR /build
COPY pyproject.toml README.md ./
COPY secscan ./secscan
COPY scripts/verify_wheel.py ./scripts/verify_wheel.py
RUN python -c "from pathlib import Path; required={'secscan/__init__.py','secscan/aws.py','secscan/cli.py','secscan/compare.py','secscan/history.py','secscan/models.py','secscan/normalize.py','secscan/policy.py','secscan/report.py','secscan/trivy.py','secscan/scanners/__init__.py','secscan/scanners/base.py','secscan/scanners/registry.py','secscan/scanners/image.py','secscan/scanners/filesystem.py','secscan/scanners/repository.py','secscan/scanners/full_repository.py','secscan/scanners/sbom.py'}; missing={path for path in required if not Path(path).is_file()}; assert not missing, f'missing source modules: {sorted(missing)}'; print('verified source tree:', ', '.join(sorted(required)))" \
    && pip wheel --no-deps --wheel-dir /wheels . \
    && python scripts/verify_wheel.py /wheels/secscan-*.whl

FROM python:3.14.7-slim-bookworm

ARG SECSCAN_VERSION=0.1.0
LABEL org.opencontainers.image.title="secscan" \
      org.opencontainers.image.description="Container-first security scanner" \
      org.opencontainers.image.version="${SECSCAN_VERSION}"

COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=gitleaks-builder /out/gitleaks /usr/local/bin/gitleaks
COPY --from=builder /wheels /wheels
RUN apt-get update \
    && apt-get install --no-install-recommends -y git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir /wheels/secscan-*.whl \
    && python -m venv /opt/semgrep \
    && /opt/semgrep/bin/pip install --no-cache-dir semgrep==1.172.0 \
    && ln -s /opt/semgrep/bin/semgrep /usr/local/bin/semgrep \
    && python -m venv /opt/checkov \
    && /opt/checkov/bin/pip install --no-cache-dir checkov==3.3.8 \
    && ln -s /opt/checkov/bin/checkov /usr/local/bin/checkov \
    && python -c "import secscan, secscan.aws, secscan.cli, secscan.compare, secscan.history, secscan.models, secscan.normalize, secscan.policy, secscan.report, secscan.trivy, secscan.scanners, secscan.scanners.base, secscan.scanners.registry, secscan.scanners.image, secscan.scanners.filesystem, secscan.scanners.repository, secscan.scanners.full_repository, secscan.scanners.sbom" \
    && semgrep --version \
    && gitleaks version \
    && checkov --version \
    && rm -rf /wheels \
    && useradd --create-home --uid 10001 secscan \
    && mkdir -p /reports /cache \
    && chown -R secscan:secscan /reports /cache

WORKDIR /app
ENV TRIVY_CACHE_DIR=/cache \
    HOME=/tmp
USER secscan
VOLUME ["/reports", "/cache"]
ENTRYPOINT ["secscan"]
CMD ["--help"]
