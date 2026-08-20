from __future__ import annotations

from pathlib import Path


def test_container_bundles_network_assessment_engines() -> None:
    dockerfile = (Path(__file__).parents[1] / "Dockerfile").read_text(encoding="utf-8")

    assert "nmap" in dockerfile
    # v3.11.1 upgrades kin-openapi to the release containing the auth-bypass fix.
    assert "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.11.1" in dockerfile
    assert "NUCLEI_TEMPLATES_VERSION=v10.4.7" in dockerfile
    assert "--branch \"${NUCLEI_TEMPLATES_VERSION}\"" in dockerfile
    assert "COPY --from=nuclei-builder /nuclei-templates /opt/nuclei-templates" in dockerfile
    assert "/opt/nuclei-templates/templates-checksum.txt" in dockerfile
    assert "nmap --version" in dockerfile
    assert "nuclei -version" in dockerfile


def test_container_scan_skips_the_nuclei_secret_detector_definition() -> None:
    workflow = (
        Path(__file__).parents[1] / ".github" / "workflows" / "ci.yml"
    ).read_text(encoding="utf-8")

    # The official template is itself a secret-detection rule. Trivy otherwise
    # treats its GCP credential regex as a credential while scanning the image.
    assert (
        "--skip-files "
        "/opt/nuclei-templates/http/global-matchers/secrets-patterns-rules.yaml"
    ) in workflow
