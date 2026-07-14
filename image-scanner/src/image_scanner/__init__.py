"""image-scanner: container image SBOM extraction (SupplyDrift Vector 2).

A single source-agnostic core scanner turns a Docker/OCI image into a
ground-truth SBOM (CycloneDX). A pluggable connector framework discovers which
images to scan per source (OCI registries, AWS ECR, Kubernetes, ...), resolves
the registry credentials needed to pull them, and the scanned result is posted
to the SupplyDrift platform's container-image sync endpoint.
"""

__version__ = "0.1.0"
