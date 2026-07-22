FROM aquasec/trivy:0.65.0 AS trivy

FROM python:3.12.11-slim-bookworm AS builder
WORKDIR /build
COPY pyproject.toml README.md ./
COPY secscan ./secscan
RUN pip wheel --no-deps --wheel-dir /wheels .

FROM python:3.12.11-slim-bookworm

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
