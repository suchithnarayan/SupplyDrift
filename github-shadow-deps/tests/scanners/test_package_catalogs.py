"""Tests for PackageCatalogScanner."""
from __future__ import annotations

from pathlib import Path

from github_inventory.config import Config
from github_inventory.discovery import FileTarget
from github_inventory.models import Severity
from github_inventory.scanners.package_catalogs import PackageCatalogScanner


def scan(content: str, file_type: str, rel_path: str = "manifest"):
    scanner = PackageCatalogScanner(Config())
    target = FileTarget(path=Path(rel_path), rel_path=rel_path, file_type=file_type)
    return scanner.scan_file_content(target, content, content.splitlines())


def test_detects_homebrew_formula_url():
    findings = scan(
        'class Stripe < Formula\n'
        '  url "https://github.com/stripe/stripe-cli/releases/download/v1.0.0/stripe.tar.gz"\n'
        '  sha256 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\n'
        "end\n",
        "homebrew_formula",
        "stripe.rb",
    )

    assert any(
        f.pattern_id == "homebrew-formula-url"
        and f.extracted_dep.endswith("stripe.tar.gz")
        and f.severity == Severity.LOW
        for f in findings
    )


def test_detects_scoop_manifest_architecture_urls():
    findings = scan(
        '{"architecture":{"64bit":{"url":"https://example.com/stripe.zip","hash":"abc"}}}',
        "scoop_manifest",
        "stripe.json",
    )

    assert any(
        f.pattern_id == "scoop-manifest-url"
        and f.extracted_dep == "https://example.com/stripe.zip"
        for f in findings
    )


def test_ignores_scoop_typed_test_fixture_snapshot():
    findings = scan(
        (
            '{"_id":"@modelcontextprotocol/server-everything",'
            '"versions":{"0.1.0":{"author":{"url":"https://anthropic.com"},'
            '"bugs":{"url":"https://github.com/modelcontextprotocol/servers/issues"},'
            '"dist":{"tarball":"https://registry.npmjs.org/pkg/-/pkg-0.1.0.tgz"}}}}'
        ),
        "scoop_manifest",
        "extensions/copilot/src/extension/mcp/test/vscode-node/fixtures/snapshots/npm-package.json",
    )

    assert findings == []


def test_detects_winget_installer_url():
    findings = scan(
        "PackageIdentifier: Stripe.CLI\n"
        "Installers:\n"
        "- Architecture: x64\n"
        "  InstallerUrl: https://example.com/stripe.msi\n"
        "  InstallerSha256: abc\n",
        "winget_manifest",
        "stripe.installer.yaml",
    )

    assert any(
        f.pattern_id == "winget-installer-url"
        and f.extracted_dep == "https://example.com/stripe.msi"
        for f in findings
    )
