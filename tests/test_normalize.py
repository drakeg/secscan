from secscan.normalize import normalize_trivy, summarize


def test_normalizes_trivy_vulnerability() -> None:
    payload = {
        "Results": [
            {
                "Target": "alpine:3.20",
                "Type": "alpine",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2026-0001",
                        "PkgName": "libexample",
                        "InstalledVersion": "1.0.0",
                        "FixedVersion": "1.0.1",
                        "Severity": "HIGH",
                        "Title": "Example vulnerability",
                        "PrimaryURL": "https://example.test/CVE-2026-0001",
                    }
                ],
            }
        ]
    }

    findings = normalize_trivy(payload)

    assert len(findings) == 1
    assert findings[0].vulnerability_id == "CVE-2026-0001"
    assert findings[0].fixed_version == "1.0.1"
    assert summarize(findings)["high"] == 1
