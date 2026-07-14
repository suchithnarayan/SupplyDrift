from github_inventory.scanners.agent_plugins import AgentPluginScanner
from github_inventory.scanners.agent_instructions import AgentInstructionScanner
from github_inventory.scanners.bazel_deps import BazelDependencyScanner
from github_inventory.scanners.binary_downloads import BinaryDownloadScanner
from github_inventory.scanners.build_external import BuildExternalScanner
from github_inventory.scanners.cdn_references import CDNReferenceScanner
from github_inventory.scanners.cicd_tools import CICDToolScanner
from github_inventory.scanners.container_images import ContainerImageScanner
from github_inventory.scanners.devcontainer import DevcontainerScanner
from github_inventory.scanners.git_dependencies import GitDependencyScanner
from github_inventory.scanners.jvm_beam_deps import JvmBeamDependencyScanner
from github_inventory.scanners.mcp_servers import MCPServerScanner
from github_inventory.scanners.mobile_deps import MobileDependencyScanner
from github_inventory.scanners.native_deps import NativeDependencyScanner
from github_inventory.scanners.package_catalogs import PackageCatalogScanner
from github_inventory.scanners.package_scripts import PackageScriptsScanner
from github_inventory.scanners.precommit_hooks import PrecommitHookScanner
from github_inventory.scanners.pulumi_iac import PulumiIaCScanner
from github_inventory.scanners.reference_tracking import ReferenceTrackingScanner
from github_inventory.scanners.registry_config import RegistryConfigScanner
from github_inventory.scanners.script_installations import ScriptInstallationScanner
from github_inventory.scanners.source_http_calls import SourceHTTPCallScanner
from github_inventory.scanners.system_packages import SystemPackageListScanner
from github_inventory.scanners.tool_versions import ToolVersionScanner
from github_inventory.scanners.unmanaged_packages import UnmanagedPackageScanner
from github_inventory.scanners.vendored_binaries import VendoredBinaryScanner

ALL_SCANNERS = [
    ScriptInstallationScanner,
    BinaryDownloadScanner,
    UnmanagedPackageScanner,
    GitDependencyScanner,
    ContainerImageScanner,
    CICDToolScanner,
    VendoredBinaryScanner,
    BuildExternalScanner,
    BazelDependencyScanner,
    PrecommitHookScanner,
    DevcontainerScanner,
    ToolVersionScanner,
    ReferenceTrackingScanner,
    RegistryConfigScanner,
    CDNReferenceScanner,
    SourceHTTPCallScanner,
    MobileDependencyScanner,
    NativeDependencyScanner,
    JvmBeamDependencyScanner,
    MCPServerScanner,
    AgentPluginScanner,
    AgentInstructionScanner,
    SystemPackageListScanner,
    PulumiIaCScanner,
    PackageScriptsScanner,
    PackageCatalogScanner,
]

__all__ = [
    "ALL_SCANNERS",
    "AgentInstructionScanner",
    "AgentPluginScanner",
    "BazelDependencyScanner",
    "BinaryDownloadScanner",
    "BuildExternalScanner",
    "CDNReferenceScanner",
    "CICDToolScanner",
    "ContainerImageScanner",
    "DevcontainerScanner",
    "GitDependencyScanner",
    "JvmBeamDependencyScanner",
    "MobileDependencyScanner",
    "NativeDependencyScanner",
    "PackageCatalogScanner",
    "PrecommitHookScanner",
    "ReferenceTrackingScanner",
    "RegistryConfigScanner",
    "ScriptInstallationScanner",
    "SourceHTTPCallScanner",
    "ToolVersionScanner",
    "UnmanagedPackageScanner",
    "VendoredBinaryScanner",
]
