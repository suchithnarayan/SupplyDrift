"""Tests for file discovery and classification."""
from __future__ import annotations

from pathlib import Path

from github_inventory.config import Config
from github_inventory.discovery import FileDiscovery

FIXTURES = Path(__file__).parent / "fixtures"


def test_discovers_workflow_files():
    discovery = FileDiscovery(FIXTURES, Config())
    targets = list(discovery.discover())
    file_types = {t.file_type for t in targets}
    assert "ci" in file_types


def test_discovers_scripts():
    discovery = FileDiscovery(FIXTURES, Config())
    targets = list(discovery.discover())
    file_types = {t.file_type for t in targets}
    assert "script" in file_types


def test_discovers_dockerfiles():
    discovery = FileDiscovery(FIXTURES, Config())
    targets = list(discovery.discover())
    file_types = {t.file_type for t in targets}
    assert "dockerfile" in file_types


def test_discovers_build_files():
    discovery = FileDiscovery(FIXTURES, Config())
    targets = list(discovery.discover())
    file_types = {t.file_type for t in targets}
    assert "build" in file_types


def test_discovers_wercker_and_snapcraft_files(tmp_path):
    (tmp_path / "wercker.yml").write_text("box: golang\n")
    (tmp_path / "snapcraft.yaml").write_text("parts: {}\n")

    discovery = FileDiscovery(tmp_path, Config())
    targets = {t.rel_path: t.file_type for t in discovery.discover()}

    assert targets["wercker.yml"] == "ci"
    assert targets["snapcraft.yaml"] == "ci"


def test_discovers_agent_instruction_files(tmp_path):
    skill = tmp_path / ".agents" / "skills" / "demo" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("# Demo\n")
    (tmp_path / "CLAUDE.md").write_text("# Agent instructions\n")

    discovery = FileDiscovery(tmp_path, Config())
    targets = {t.rel_path: t.file_type for t in discovery.discover()}

    assert targets[".agents/skills/demo/SKILL.md"] == "agent_instruction"
    assert targets["CLAUDE.md"] == "agent_instruction"


def test_discovers_go_source_files_for_agent_repos(tmp_path):
    repo = tmp_path / "demo-mcp-server"
    repo.mkdir()
    (repo / "main.go").write_text("package main\n")

    discovery = FileDiscovery(repo, Config())
    targets = {t.rel_path: t.file_type for t in discovery.discover()}

    assert targets["main.go"] == "source_code"


def test_ignores_ordinary_go_source_files(tmp_path):
    (tmp_path / "main.go").write_text("package main\n")

    discovery = FileDiscovery(tmp_path, Config())
    targets = {t.rel_path: t.file_type for t in discovery.discover()}

    assert "main.go" not in targets


def test_discovers_json_mcp_config_by_content(tmp_path):
    (tmp_path / "gemini-extension.json").write_text(
        '{"mcpServers": {"stripe": {"httpUrl": "https://mcp.stripe.com"}}}\n'
    )

    discovery = FileDiscovery(tmp_path, Config())
    targets = {t.rel_path: t.file_type for t in discovery.discover()}

    assert targets["gemini-extension.json"] == "mcp_config"


def test_does_not_classify_i18n_json_as_mcp_config(tmp_path):
    loc = tmp_path / "translations" / "main.i18n.json"
    loc.parent.mkdir()
    loc.write_text(
        '{"contents": {"settings": {"mcpServers": "MCP servers", "command": "Command"}}}\n'
    )

    discovery = FileDiscovery(tmp_path, Config())
    targets = {t.rel_path: t.file_type for t in discovery.discover()}

    assert "translations/main.i18n.json" not in targets


def test_discovers_targeted_agent_markdown_docs(tmp_path):
    (tmp_path / "README.md").write_text(
        "# Demo\n\nRun `npx -y @stripe/mcp --api-key sk_test` for Model Context Protocol.\n"
    )

    discovery = FileDiscovery(tmp_path, Config())
    targets = {t.rel_path: t.file_type for t in discovery.discover()}

    assert targets["README.md"] == "agent_instruction"


def test_keeps_generic_install_readme_out_of_scan(tmp_path):
    (tmp_path / "README.md").write_text(
        "# Installation Guide\n\n```bash\ncurl https://example.com/install.sh | bash\n```\n"
    )

    discovery = FileDiscovery(tmp_path, Config())
    targets = {t.rel_path: t.file_type for t in discovery.discover()}

    assert "README.md" not in targets


def test_keeps_generic_named_install_docs_out_of_scan(tmp_path):
    (tmp_path / "INSTALL.md").write_text(
        "# Install\n\n```bash\npip install example-tool\nnpx create-example@latest\n```\n"
    )
    setup = tmp_path / "docs" / "getting-started" / "setup.md"
    setup.parent.mkdir(parents=True)
    setup.write_text(
        "# Setup\n\n```bash\nbrew install example\ncurl https://example.com/install.sh | bash\n```\n"
    )

    discovery = FileDiscovery(tmp_path, Config())
    targets = {t.rel_path: t.file_type for t in discovery.discover()}

    assert "INSTALL.md" not in targets
    assert "docs/getting-started/setup.md" not in targets


def test_keeps_site_docs_markdown_out_of_agent_instruction_scan(tmp_path):
    doc = tmp_path / "src" / "frontend" / "src" / "content" / "docs" / "get-started" / "install-cli.mdx"
    doc.parent.mkdir(parents=True)
    doc.write_text(
        "# Install\n\n```bash\ncurl https://example.com/install.sh | bash\nnpm install -g tool\n```\n"
    )

    discovery = FileDiscovery(tmp_path, Config())
    targets = {t.rel_path: t.file_type for t in discovery.discover()}

    assert "src/frontend/src/content/docs/get-started/install-cli.mdx" not in targets


def test_keeps_website_blog_markdown_out_of_agent_instruction_scan(tmp_path):
    doc = tmp_path / "website" / "blog" / "2023-07-14-local-llms" / "index.mdx"
    doc.parent.mkdir(parents=True)
    doc.write_text(
        "# Use autogen for local LLMs\n\n```bash\ngit clone https://github.com/lm-sys/FastChat.git\n```\n"
    )

    discovery = FileDiscovery(tmp_path, Config())
    targets = {t.rel_path: t.file_type for t in discovery.discover()}

    assert "website/blog/2023-07-14-local-llms/index.mdx" not in targets


def test_keeps_plural_blogs_markdown_out_of_agent_instruction_scan(tmp_path):
    doc = tmp_path / "blogs" / "2020" / "12" / "03" / "chromebook-get-started.md"
    doc.parent.mkdir(parents=True)
    doc.write_text(
        "# Get Started\n\n```sh\nwget -qO- https://example.com/install.sh | bash\n```\n"
    )

    discovery = FileDiscovery(tmp_path, Config())
    targets = {t.rel_path: t.file_type for t in discovery.discover()}

    assert "blogs/2020/12/03/chromebook-get-started.md" not in targets


def test_discovers_package_catalogs_by_content(tmp_path):
    (tmp_path / "stripe.rb").write_text(
        'class Stripe < Formula\n  url "https://github.com/stripe/stripe-cli/archive/v1.0.0.tar.gz"\nend\n'
    )
    (tmp_path / "stripe.json").write_text(
        '{"version":"1.0.0","architecture":{"64bit":{"url":"https://example.com/stripe.zip","hash":"abc"}}}\n'
    )
    (tmp_path / "stripe.installer.yaml").write_text(
        "PackageIdentifier: Stripe.CLI\nInstallers:\n- InstallerUrl: https://example.com/stripe.msi\n"
    )

    discovery = FileDiscovery(tmp_path, Config())
    targets = {t.rel_path: t.file_type for t in discovery.discover()}

    assert targets["stripe.rb"] == "homebrew_formula"
    assert targets["stripe.json"] == "scoop_manifest"
    assert targets["stripe.installer.yaml"] == "winget_manifest"


def test_does_not_classify_generic_report_json_as_scoop_manifest(tmp_path):
    report = tmp_path / "src" / "test-resources" / "axe-result.json"
    report.parent.mkdir(parents=True)
    report.write_text(
        '{"version":"2.1.0","runs":[{"results":[{"url":"https://www.w3.org/WAI/demos/bad/before/home.html",'
        '"hash":"abc123"}]}]}\n'
    )

    discovery = FileDiscovery(tmp_path, Config())
    targets = {t.rel_path: t.file_type for t in discovery.discover()}

    assert "src/test-resources/axe-result.json" not in targets


def test_discovers_go_source_with_emitted_install_command(tmp_path):
    (tmp_path / "root.go").write_text('package main\nconst msg = "Run npx skills add stripe/ai"\n')

    discovery = FileDiscovery(tmp_path, Config())
    targets = {t.rel_path: t.file_type for t in discovery.discover()}

    assert targets["root.go"] == "source_code"


def test_excludes_git_directory(tmp_path):
    git_file = tmp_path / ".git" / "config"
    git_file.parent.mkdir()
    git_file.write_text("[core]\n    repositoryformatversion = 0\n")
    (tmp_path / "Makefile").write_text("build:\n\tgo build ./...\n")

    discovery = FileDiscovery(tmp_path, Config())
    targets = list(discovery.discover())
    rel_paths = {t.rel_path for t in targets}
    assert not any(".git" in p for p in rel_paths)


def test_custom_exclude_path(tmp_path):
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "install.sh").write_text("#!/bin/bash\necho hi\n")
    (tmp_path / "install.sh").write_text("#!/bin/bash\ncurl https://example.com | bash\n")

    config = Config(exclude_paths=["vendor/**"])
    discovery = FileDiscovery(tmp_path, config)
    targets = list(discovery.discover())
    rel_paths = {t.rel_path for t in targets}
    assert not any(p.startswith("vendor/") for p in rel_paths)
    assert "install.sh" in rel_paths
