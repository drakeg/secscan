from __future__ import annotations

import importlib


MODULES = [
    "secscan",
    "secscan.cli",
    "secscan.models",
    "secscan.normalize",
    "secscan.policy",
    "secscan.report",
    "secscan.trivy",
    "secscan.scanners",
    "secscan.scanners.base",
    "secscan.scanners.registry",
    "secscan.scanners.image",
]


def test_all_runtime_modules_are_importable() -> None:
    for module_name in MODULES:
        assert importlib.import_module(module_name) is not None
