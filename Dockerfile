FROM aquasec/trivy:0.72.0 AS trivy

FROM python:3.14.6-slim-bookworm AS builder
WORKDIR /build
COPY pyproject.toml README.md ./
COPY secscan ./secscan
COPY scripts/verify_wheel.py ./scripts/verify_wheel.py
RUN python -c "from pathlib import Path; required={'secscan/__init__.py','secscan/cli.py','secscan/models.py','secscan/normalize.py','secscan/policy.py','secscan/report.py','secscan/trivy.py','secscan/scanners/__init__.py','secscan/scanners/base.py','secscan/scanners/registry.py','secscan/scanners/image.py','secscan/scanners/filesystem.py'}; missing={path for path in required if not Path(path).is_file()}; assert not missing, f'missing source modules: {sorted(missing)}'; print('verified source tree:', ', '.join(sorted(required)))" \
    && pip wheel --no-deps --wheel-dir /wheels . \
    && python scripts/verify_wheel.py /wheels/secscan-*.whl

FROM python:3.14.6-slim-bookworm

ARG SECSCAN_VERSION=0.1.0
LABEL org.opencontainers.image.title="secscan" \
      org.opencontainers.image.description="Container-first security scanner" \
      org.opencontainers.image.version="${SECSCAN_VERSION}"

COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/secscan-*.whl \
    && python -c "import secscan, secscan.cli, secscan.models, secscan.normalize, secscan.policy, secscan.report, secscan.trivy, secscan.scanners, secscan.scanners.base, secscan.scanners.registry, secscan.scanners.image, secscan.scanners.filesystem" \
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
