from __future__ import annotations

from collections.abc import Iterable

from secscan.scanners.base import Scanner, ScannerCapability


class ScannerRegistry:
    def __init__(self, scanners: Iterable[Scanner] = ()) -> None:
        self._scanners: dict[str, Scanner] = {}
        for scanner in scanners:
            self.register(scanner)

    def register(self, scanner: Scanner) -> None:
        name = scanner.capability.name
        if name in self._scanners:
            raise ValueError(f"scanner already registered: {name}")
        self._scanners[name] = scanner

    def get(self, name: str) -> Scanner:
        try:
            return self._scanners[name]
        except KeyError as exc:
            available = ", ".join(sorted(self._scanners)) or "none"
            raise ValueError(f"unknown scanner '{name}'; available scanners: {available}") from exc

    def capabilities(self) -> tuple[ScannerCapability, ...]:
        return tuple(self._scanners[name].capability for name in sorted(self._scanners))


def build_default_registry() -> ScannerRegistry:
    from secscan.scanners.filesystem import FilesystemScanner
    from secscan.scanners.image import ImageScanner

    return ScannerRegistry([ImageScanner(), FilesystemScanner()])
