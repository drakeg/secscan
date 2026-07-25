from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import date
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
    published_date: date | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        if self.published_date is None:
            data.pop("published_date")
        else:
            data["published_date"] = self.published_date.isoformat()
        return data
