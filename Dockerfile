FROM aquasec/trivy:0.65.0 AS trivy

FROM python:3.12.13-slim-bookworm AS builder
WORKDIR /build
COPY pyproject.toml README.md ./
RUN mkdir -p secscan scripts
COPY secscan/__init__.py ./secscan/__init__.py
COPY secscan/cli.py ./secscan/cli.py
COPY secscan/models.py ./secscan/models.py
COPY secscan/normalize.py ./secscan/normalize.py
COPY secscan/policy.py ./secscan/policy.py
COPY secscan/report.py ./secscan/report.py
COPY secscan/trivy.py ./secscan/trivy.py
COPY scripts/verify_wheel.py ./scripts/verify_wheel.py
RUN python -c "from pathlib import Path; required={'__init__.py','cli.py','models.py','normalize.py','policy.py','report.py','trivy.py'}; present={p.name for p in Path('secscan').glob('*.py')}; missing=required-present; assert not missing, f'missing source modules: {sorted(missing)}'; print('verified source tree:', ', '.join(sorted(present)))" \
    && pip wheel --no-deps --wheel-dir /wheels . \
    && python scripts/verify_wheel.py /wheels/secscan-*.whl

FROM python:3.12.13-slim-bookworm

ARG SECSCAN_VERSION=0.1.0
LABEL org.opencontainers.image.title="secscan" \
      org.opencontainers.image.description="Container-first security scanner" \
      org.opencontainers.image.version="${SECSCAN_VERSION}"

COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/secscan-*.whl \
    && python -c "import secscan, secscan.cli, secscan.models, secscan.normalize, secscan.policy, secscan.report, secscan.trivy" \
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
