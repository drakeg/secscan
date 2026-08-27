FROM aquasec/trivy:0.74.0 AS trivy

FROM golang:1.25-bookworm AS gitleaks-builder
RUN mkdir -p /out \
    && GOBIN=/out go install github.com/zricethezav/gitleaks/v8@v8.30.1

FROM golang:1.26-bookworm AS nuclei-builder
ARG NUCLEI_TEMPLATES_VERSION=v10.4.7
ARG NUCLEI_TEMPLATES_COMMIT=83234ce456da3e90dda86dfbc5e605e64a846df3
RUN mkdir -p /out \
    && GOBIN=/out go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.11.1 \
    && git init /nuclei-templates \
    && git -C /nuclei-templates remote add origin \
        https://github.com/projectdiscovery/nuclei-templates.git \
    && git -C /nuclei-templates fetch --depth 1 origin \
        "refs/tags/${NUCLEI_TEMPLATES_VERSION}" \
    && test "$(git -C /nuclei-templates rev-parse 'FETCH_HEAD^{commit}')" = "${NUCLEI_TEMPLATES_COMMIT}" \
    && git -C /nuclei-templates checkout --detach "${NUCLEI_TEMPLATES_COMMIT}" \
    && rm -rf /nuclei-templates/.git \
    && printf '%s\n' "${NUCLEI_TEMPLATES_VERSION}" > /nuclei-templates/.secscan-template-version \
    && printf '%s\n' "${NUCLEI_TEMPLATES_COMMIT}" > /nuclei-templates/.secscan-template-commit

FROM python:3.14.7-slim-bookworm AS python-scanner-tools
RUN python -m venv /opt/semgrep \
    && /opt/semgrep/bin/pip install --no-cache-dir semgrep==1.172.0 \
    && python -m venv /opt/checkov \
    && /opt/checkov/bin/pip install --no-cache-dir checkov==3.3.8

FROM python:3.14.7-slim-bookworm AS builder
WORKDIR /build
COPY pyproject.toml README.md ./
COPY secscan ./secscan
COPY scripts/verify_wheel.py ./scripts/verify_wheel.py
RUN python -c "from pathlib import Path; required={'secscan/__init__.py','secscan/auth.py','secscan/aws.py','secscan/cli.py','secscan/compare.py','secscan/history.py','secscan/models.py','secscan/normalize.py','secscan/policy.py','secscan/report.py','secscan/ssh_credentials.py','secscan/ssh_host_trust.py','secscan/ssh_host_trust_web.py','secscan/trivy.py','secscan/web.py','secscan/web_assets/__init__.py','secscan/web_assets/index.html','secscan/web_assets/ssh_credentials.js','secscan/scanners/__init__.py','secscan/scanners/base.py','secscan/scanners/registry.py','secscan/scanners/image.py','secscan/scanners/filesystem.py','secscan/scanners/repository.py','secscan/scanners/full_repository.py','secscan/scanners/network.py','secscan/scanners/linux_host.py','secscan/scanners/sbom.py'}; missing={path for path in required if not Path(path).is_file()}; assert not missing, f'missing source modules: {sorted(missing)}'; print('verified source tree:', ', '.join(sorted(required)))" \
    && pip wheel --no-deps --wheel-dir /wheels . \
    && python scripts/verify_wheel.py /wheels/secscan-*.whl

FROM python:3.14.7-slim-bookworm

ARG SECSCAN_VERSION=0.1.0
ARG NUCLEI_TEMPLATES_VERSION=v10.4.7
ARG NUCLEI_TEMPLATES_COMMIT=83234ce456da3e90dda86dfbc5e605e64a846df3
LABEL org.opencontainers.image.title="secscan" \
      org.opencontainers.image.description="Container-first security scanner" \
      org.opencontainers.image.version="${SECSCAN_VERSION}"

COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=gitleaks-builder /out/gitleaks /usr/local/bin/gitleaks
COPY --from=nuclei-builder /out/nuclei /usr/local/bin/nuclei
COPY --from=nuclei-builder /nuclei-templates /opt/nuclei-templates
COPY --from=python-scanner-tools /opt/semgrep /opt/semgrep
COPY --from=python-scanner-tools /opt/checkov /opt/checkov
RUN apt-get update \
    && apt-get install --no-install-recommends -y git ca-certificates nmap openssh-client \
    && rm -rf /var/lib/apt/lists/* \
    && ln -s /opt/semgrep/bin/semgrep /usr/local/bin/semgrep \
    && ln -s /opt/checkov/bin/checkov /usr/local/bin/checkov \
    && semgrep --version \
    && gitleaks version \
    && checkov --version \
    && nmap --version \
    && ssh -V \
    && ssh-keyscan -h >/dev/null 2>&1 || true \
    && nuclei -version \
    && test "$(cat /opt/nuclei-templates/.secscan-template-version)" = "${NUCLEI_TEMPLATES_VERSION}" \
    && test "$(cat /opt/nuclei-templates/.secscan-template-commit)" = "${NUCLEI_TEMPLATES_COMMIT}" \
    && test -s /opt/nuclei-templates/templates-checksum.txt \
    && useradd --create-home --uid 10001 secscan \
    && mkdir -p /reports /cache \
    && chown -R secscan:secscan /reports /cache

COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/secscan-*.whl \
    && python -c "import secscan, secscan.auth, secscan.aws, secscan.cli, secscan.compare, secscan.history, secscan.models, secscan.normalize, secscan.policy, secscan.report, secscan.ssh_credentials, secscan.ssh_host_trust, secscan.ssh_host_trust_web, secscan.trivy, secscan.scanners, secscan.scanners.base, secscan.scanners.registry, secscan.scanners.image, secscan.scanners.filesystem, secscan.scanners.repository, secscan.scanners.full_repository, secscan.scanners.network, secscan.scanners.linux_host, secscan.scanners.sbom" \
    && rm -rf /wheels

WORKDIR /app
ENV TRIVY_CACHE_DIR=/cache \
    HOME=/tmp
USER secscan
VOLUME ["/reports", "/cache"]
ENTRYPOINT ["secscan"]
CMD ["--help"]
