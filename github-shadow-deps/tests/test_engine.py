"""Integration test: run full scan engine on fixture directory."""
from __future__ import annotations

from pathlib import Path

from github_inventory.config import Config
from github_inventory.engine import ScanEngine
from github_inventory.models import Category, Severity

FIXTURES = Path(__file__).parent / "fixtures"


def test_full_scan_finds_critical_findings():
    config = Config()
    engine = ScanEngine(FIXTURES, config)
    result = engine.run()

    assert result.files_scanned > 0
    assert len(result.findings) > 0

    # Should find at least some critical/high findings
    high_plus = [f for f in result.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    assert len(high_plus) > 0, "Expected at least one HIGH/CRITICAL finding in fixtures"


def test_full_scan_covers_multiple_categories():
    config = Config()
    engine = ScanEngine(FIXTURES, config)
    result = engine.run()

    categories = {f.category for f in result.findings}
    assert len(categories) >= 3, f"Expected >=3 categories, got: {categories}"


def test_findings_are_sorted_by_severity():
    config = Config()
    engine = ScanEngine(FIXTURES, config)
    result = engine.run()

    orders = [f.severity.sort_order for f in result.findings]
    assert orders == sorted(orders), "Findings should be sorted by severity (CRITICAL first)"


def test_no_duplicate_findings():
    config = Config()
    engine = ScanEngine(FIXTURES, config)
    result = engine.run()

    keys = [(f.file_path, f.line_number, f.pattern_id, f.extracted_dep) for f in result.findings]
    assert len(keys) == len(set(keys)), "Duplicate findings detected"


def test_engine_keeps_multiple_dependencies_on_one_install_line(tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.12-slim\n"
        "RUN pip install pytest python-dotenv azure-identity\n",
        encoding="utf-8",
    )

    result = ScanEngine(tmp_path, Config()).run()

    deps = {
        f.extracted_dep
        for f in result.findings
        if f.pattern_id == "pip-install-ci"
    }
    assert {"pytest", "python-dotenv", "azure-identity"} <= deps


def test_script_installation_findings_present():
    config = Config()
    engine = ScanEngine(FIXTURES, config)
    result = engine.run()

    script_findings = [f for f in result.findings if f.category == Category.SCRIPT_INSTALLATION]
    assert len(script_findings) > 0, "Expected script installation findings from install.sh fixture"


def test_cicd_tool_findings_present():
    config = Config()
    engine = ScanEngine(FIXTURES, config)
    result = engine.run()

    cicd_findings = [f for f in result.findings if f.category == Category.CICD_TOOL]
    assert len(cicd_findings) > 0, "Expected CI/CD tool findings from github_actions.yml fixture"


def test_ignore_rule_suppresses_finding():
    from github_inventory.config import Config, IgnoreRule
    config = Config(ignore=[IgnoreRule(pattern="get.docker.com", reason="internal approved")])
    engine = ScanEngine(FIXTURES, config)
    result = engine.run()

    docker_findings = [f for f in result.findings if "get.docker.com" in f.extracted_dep]
    assert docker_findings == [], "Ignored pattern should suppress finding"


def test_reference_tracking_detects_references():
    """Test that reference tracking scanner detects script/file references."""
    config = Config()
    engine = ScanEngine(FIXTURES, config)
    result = engine.run()

    # Should find SCRIPT_REFERENCE or FILE_REFERENCE findings
    ref_findings = [f for f in result.findings
                    if f.category in (Category.SCRIPT_REFERENCE, Category.FILE_REFERENCE)]
    assert len(ref_findings) > 0, "Expected reference findings from fixtures"

    # Should detect the GitHub Actions reference to ./scripts/deploy.sh
    deploy_refs = [f for f in ref_findings if "deploy.sh" in f.extracted_dep]
    assert len(deploy_refs) > 0, "Expected reference to deploy.sh from github_actions.yml"


def test_referenced_files_are_scanned():
    """Test Phase 1.5: referenced files are automatically scanned."""
    config = Config()
    engine = ScanEngine(FIXTURES, config)
    result = engine.run()

    # The github_actions.yml references ./scripts/deploy.sh
    # That script should be scanned and its shadow dependencies found
    deploy_findings = [f for f in result.findings
                      if f.file_path.endswith("deploy.sh")]

    # deploy.sh contains "curl | bash" and "npm install -g"
    # So we should have findings from that file
    assert len(deploy_findings) > 0, "Expected findings from referenced deploy.sh script"

    # Verify specific shadow dependencies in deploy.sh
    deploy_categories = {f.category for f in deploy_findings}
    assert Category.SCRIPT_INSTALLATION in deploy_categories or \
           Category.UNMANAGED_PACKAGE in deploy_categories, \
           "deploy.sh should have shadow dependency findings"


def test_dockerfile_copy_reference_scanned():
    """Test that scripts referenced in Dockerfile COPY are scanned."""
    config = Config()
    engine = ScanEngine(FIXTURES, config)
    result = engine.run()

    # Dockerfile COPYs scripts/setup.sh
    # That script should be scanned
    setup_findings = [f for f in result.findings
                     if "setup.sh" in f.file_path]

    # setup.sh contains "cargo install" command
    assert len(setup_findings) > 0, "Expected findings from referenced setup.sh script"


def test_no_duplicate_scanning_of_references():
    """Test that referenced files are scanned exactly once (no duplicates)."""
    config = Config()
    engine = ScanEngine(FIXTURES, config)
    result = engine.run()

    # Count findings per file to ensure no duplicates from re-scanning
    file_finding_counts = {}
    for f in result.findings:
        key = (f.file_path, f.line_number, f.pattern_id, f.extracted_dep)
        file_finding_counts[key] = file_finding_counts.get(key, 0) + 1

    # All should be 1 (no duplicates)
    duplicates = {k: v for k, v in file_finding_counts.items() if v > 1}
    assert not duplicates, f"Found duplicate findings: {duplicates}"


def test_engine_scans_piped_heredoc_generated_config(tmp_path):
    workflow = tmp_path / ".github" / "workflows" / "mcp.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: |\n"
        "          cat <<EOF | node start_mcp_gateway.cjs\n"
        "          {\"container\": \"ghcr.io/github/github-mcp-server:v1.0.4\"}\n"
        "          EOF\n",
        encoding="utf-8",
    )

    result = ScanEngine(tmp_path, Config()).run()

    assert any(
        f.pattern_id == "json-container-image"
        and f.extracted_dep == "ghcr.io/github/github-mcp-server:v1.0.4"
        for f in result.findings
    )


def test_engine_strips_plain_printed_heredoc_config(tmp_path):
    script = tmp_path / "show-help.sh"
    script.write_text(
        "cat <<EOF\n"
        "{\"container\": \"ghcr.io/github/github-mcp-server:v1.0.4\"}\n"
        "EOF\n",
        encoding="utf-8",
    )

    result = ScanEngine(tmp_path, Config()).run()

    assert not any(f.pattern_id == "json-container-image" for f in result.findings)


def test_reference_findings_have_correct_metadata():
    """Test that reference findings have correct category and severity."""
    config = Config()
    engine = ScanEngine(FIXTURES, config)
    result = engine.run()

    ref_findings = [f for f in result.findings if f.category == Category.SCRIPT_REFERENCE]

    if ref_findings:  # Only test if we have reference findings
        for finding in ref_findings:
            # Should have extracted a file path
            assert finding.extracted_dep, "Reference finding should extract a file path"
            # Should have reasonable severity (LOW to MEDIUM for most references)
            assert finding.severity in (Severity.LOW, Severity.MEDIUM, Severity.HIGH), \
                f"Reference severity should be reasonable, got: {finding.severity}"
