from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from secscan.trivy import scan_image


def test_image_scan_passes_credentials_only_in_child_environment(tmp_path: Path, monkeypatch) -> None:
    captured: dict[str, object] = {}
    monkeypatch.setenv("SECSCAN_TEST_PARENT", "preserved")

    def fake_run(command: list[str], **kwargs: object) -> SimpleNamespace:
        captured["command"] = command
        captured["environment"] = kwargs["env"]
        output = Path(command[command.index("--output") + 1])
        output.write_text("{}", encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("secscan.trivy.subprocess.run", fake_run)
    environment = {
        "AWS_ACCESS_KEY_ID": "temporary-access",
        "AWS_SECRET_ACCESS_KEY": "temporary-secret",
        "AWS_SESSION_TOKEN": "temporary-token",
    }

    assert scan_image("registry.example/app@sha256:digest", environment=environment) == {}
    assert "temporary-access" not in " ".join(captured["command"])
    assert captured["environment"]["SECSCAN_TEST_PARENT"] == "preserved"
    assert captured["environment"]["AWS_SESSION_TOKEN"] == "temporary-token"
