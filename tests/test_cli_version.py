from importlib.metadata import PackageNotFoundError

import secscan.cli as cli


def test_secscan_version_uses_installed_distribution(monkeypatch):
    monkeypatch.setattr(cli, "version", lambda package: "9.8.7")

    assert cli._secscan_version() == "9.8.7"


def test_secscan_version_falls_back_when_distribution_missing(monkeypatch):
    def missing(_package: str) -> str:
        raise PackageNotFoundError

    monkeypatch.setattr(cli, "version", missing)

    assert cli._secscan_version() == "unknown"
