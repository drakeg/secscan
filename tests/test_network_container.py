from __future__ import annotations

from pathlib import Path


def test_container_bundles_network_assessment_engines() -> None:
    dockerfile = (Path(__file__).parents[1] / "Dockerfile").read_text(encoding="utf-8")

    assert "nmap" in dockerfile
    # v3.11.1 upgrades kin-openapi to the release containing the auth-bypass fix.
    assert "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.11.1" in dockerfile
    assert "NUCLEI_TEMPLATES_VERSION=v10.4.7" in dockerfile
    assert "NUCLEI_TEMPLATES_COMMIT=83234ce456da3e90dda86dfbc5e605e64a846df3" in dockerfile
    assert '"refs/tags/${NUCLEI_TEMPLATES_VERSION}"' in dockerfile
    assert "rev-parse 'FETCH_HEAD^{commit}')\" = \"${NUCLEI_TEMPLATES_COMMIT}\"" in dockerfile
    assert 'checkout --detach "${NUCLEI_TEMPLATES_COMMIT}"' in dockerfile
    assert "COPY --from=nuclei-builder /nuclei-templates /opt/nuclei-templates" in dockerfile
    assert "/opt/nuclei-templates/.secscan-template-commit" in dockerfile
    assert "/opt/nuclei-templates/templates-checksum.txt" in dockerfile
    assert "nmap --version" in dockerfile
    assert "nuclei -version" in dockerfile


def test_container_security_gate_is_vulnerability_only() -> None:
    workflow = (
        Path(__file__).parents[1] / ".github" / "workflows" / "ci.yml"
    ).read_text(encoding="utf-8")

    # This gate exists to reject fixable CRITICAL image vulnerabilities. Limiting
    # Trivy to the vuln scanner avoids secret-scanning the embedded Nuclei secret
    # detection rule and removes the need for a scanner-specific skip exception.
    assert "--scanners vuln" in workflow
    assert "secrets-patterns-rules.yaml" not in workflow
