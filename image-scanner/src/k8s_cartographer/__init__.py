"""k8s-cartographer: Kubernetes cluster-wide dependency cartography (SupplyDrift Vector 3).

Enumerates running workloads across a cluster, resolves their container images,
flags shadow deployments (workloads with no sanctioned delivery path) and mutable
image references, and emits a SupplyDrift sync payload for the platform.
"""

__version__ = "0.1.0"
