"""Shared test helpers: a fake extractor, config builders, and a CycloneDX doc."""
from __future__ import annotations

from typing import Any

from image_scanner.config import RegistryConfig, ServiceConfig
from image_scanner.core.extractors.base import SbomExtractor
from image_scanner.models import ImageFilter, RegistryAuth


def registry_cfg(name: str, type: str, connection=None, aws_session=None, **filter_kwargs) -> RegistryConfig:
    return RegistryConfig(
        name=name,
        type=type,
        connection=connection or {},
        filters=ImageFilter(**filter_kwargs),
        aws_session=aws_session,
    )


def service_cfg(name: str, type: str, connection=None, discovery=None, aws_session=None, **filter_kwargs) -> ServiceConfig:
    return ServiceConfig(
        name=name,
        type=type,
        connection=connection or {},
        discovery=discovery or {},
        filters=ImageFilter(**filter_kwargs),
        aws_session=aws_session,
    )


def sample_cyclonedx(name: str = "openssl") -> dict[str, Any]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {
                "type": "library",
                "name": name,
                "version": "3.0.2",
                "purl": f"pkg:deb/ubuntu/{name}@3.0.2",
                "properties": [
                    {"name": "syft:location:0:path", "value": "/var/lib/dpkg/status"},
                    {"name": "syft:package:type", "value": "deb"},
                ],
            }
        ],
    }


class FakeExtractor(SbomExtractor):
    name = "fake"

    def __init__(self):
        self.calls: list[tuple[str, RegistryAuth | None]] = []

    def available(self) -> bool:
        return True

    def extract(self, image_ref: str, auth: RegistryAuth | None = None) -> dict[str, Any]:
        self.calls.append((image_ref, auth))
        return sample_cyclonedx()
