"""The pluggable SBOM-extraction backend interface.

A backend takes a pullable image reference (plus optional pull credentials) and
returns a CycloneDX JSON document. The default backend wraps ``syft``; a native
backend (dpkg/rpm/apk + ``go version -m`` + ELF) can be added behind the same
interface without touching the connectors or pipeline.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from ...models import RegistryAuth


class ExtractorError(RuntimeError):
    """Raised when an extractor backend fails to produce an SBOM."""


class SbomExtractor(ABC):
    name: str = "base"

    @abstractmethod
    def available(self) -> bool:
        """True when the backend can run (e.g. the binary is installed)."""

    @abstractmethod
    def extract(self, image_ref: str, auth: RegistryAuth | None = None) -> dict[str, Any]:
        """Return a CycloneDX JSON document for the image reference."""
