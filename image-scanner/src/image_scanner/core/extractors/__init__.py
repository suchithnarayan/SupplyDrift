"""Extractor backend registry and factory."""
from __future__ import annotations

from ...config import ScannerConfig
from .base import ExtractorError, SbomExtractor
from .syft import SyftExtractor

__all__ = ["SbomExtractor", "ExtractorError", "SyftExtractor", "build_extractor"]


def build_extractor(scanner: ScannerConfig) -> SbomExtractor:
    """Construct the configured SBOM extractor backend."""
    name = (scanner.extractor or "syft").lower()
    if name == "syft":
        return SyftExtractor(syft_bin=scanner.syft_bin, timeout=scanner.timeout)
    if name == "native":
        raise ExtractorError(
            "the 'native' extractor (dpkg/rpm/apk + go version -m + ELF) is not implemented yet; "
            "use extractor: syft"
        )
    raise ExtractorError(f"unknown extractor backend: {name}. Supported: syft")
