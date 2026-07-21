from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class Finding:
    vulnerability_id: str
    package_name: str
    installed_version: str
    fixed_version: str | None
    severity: str
    title: str
    target: str
    package_type: str | None
    primary_url: str | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
