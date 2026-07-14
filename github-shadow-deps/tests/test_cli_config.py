"""Target configuration trust and bounded ignore-rule behavior."""
from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from github_inventory.cli import cli
from github_inventory.config import Config, IgnoreRule, MAX_IGNORE_RULES


def _target_with_suppressing_config(tmp_path):
    target = tmp_path / "sample-repo"
    target.mkdir()
    (target / "Dockerfile").write_text(
        "FROM alpine:3.22\nRUN curl -fsSL https://get.docker.com | sh\n",
        encoding="utf-8",
    )
    (target / ".github-inventory.yml").write_text(
        'ignore:\n  - pattern: ".*"\n    reason: target-owned suppression\n',
        encoding="utf-8",
    )
    return target


def _invoke_json(*args: str):
    runner = CliRunner()
    return runner.invoke(
        cli,
        ["scan", *args, "--format", "json", "--fail-on", "never"],
        catch_exceptions=False,
    )


def _json_payload(result):
    start = result.output.find("{")
    assert start >= 0, result.output
    return json.loads(result.output[start:])


def test_target_config_is_not_trusted_by_default(tmp_path):
    target = _target_with_suppressing_config(tmp_path)

    result = _invoke_json(str(target))

    assert result.exit_code == 0
    assert _json_payload(result)["summary"]["total_findings"] > 0


def test_target_config_requires_explicit_opt_in(tmp_path):
    target = _target_with_suppressing_config(tmp_path)

    result = _invoke_json(str(target), "--trust-target-config")

    assert result.exit_code == 0
    assert "trusting target-owned" in result.output
    assert _json_payload(result)["summary"]["total_findings"] == 0


def test_noncanonical_target_config_name_is_ignored(tmp_path):
    target = _target_with_suppressing_config(tmp_path)
    canonical = target / ".github-inventory.yml"
    canonical.rename(target / (".binary" + "-inventory.yml"))

    result = _invoke_json(str(target), "--trust-target-config")

    assert result.exit_code == 0
    assert _json_payload(result)["summary"]["total_findings"] > 0


def test_target_config_cannot_escape_through_symlink(tmp_path):
    target = _target_with_suppressing_config(tmp_path)
    outside = tmp_path / "outside-policy.yml"
    outside.write_text('ignore:\n  - pattern: ".*"\n', encoding="utf-8")
    target_config = target / ".github-inventory.yml"
    target_config.unlink()
    target_config.symlink_to(outside)

    result = _invoke_json(str(target), "--trust-target-config")

    assert result.exit_code == 2
    assert "must stay inside the target" in result.output


def test_config_loads_exact_external_file(tmp_path):
    target = _target_with_suppressing_config(tmp_path)
    external = tmp_path / "trusted-policy.yml"
    external.write_text(
        'ignore:\n  - pattern: ".*"\n    reason: trusted policy\n',
        encoding="utf-8",
    )

    result = _invoke_json(str(target), "--config", str(external))

    assert result.exit_code == 0
    assert _json_payload(result)["summary"]["total_findings"] == 0


def test_config_and_target_trust_are_mutually_exclusive(tmp_path):
    target = _target_with_suppressing_config(tmp_path)
    external = tmp_path / "trusted-policy.yml"
    external.write_text("{}\n", encoding="utf-8")

    result = CliRunner().invoke(
        cli,
        [
            "scan",
            str(target),
            "--config",
            str(external),
            "--trust-target-config",
        ],
    )

    assert result.exit_code == 2
    assert "mutually exclusive" in result.output


def test_invalid_config_schema_exits_two(tmp_path):
    target = _target_with_suppressing_config(tmp_path)
    external = tmp_path / "invalid.yml"
    external.write_text("ignore: not-a-list\n", encoding="utf-8")

    result = _invoke_json(str(target), "--config", str(external))

    assert result.exit_code == 2
    assert "must be a list" in result.output


@pytest.mark.parametrize(
    "config_text, expected",
    [
        ("version: 2\n", "version"),
        ("unknown_policy: true\n", "unknown key"),
        ("ignore:\n  - pattern: safe\n    typo: value\n", "unknown key"),
    ],
)
def test_config_rejects_unknown_keys_and_versions(
    tmp_path, config_text, expected
):
    target = _target_with_suppressing_config(tmp_path)
    external = tmp_path / "invalid-policy.yml"
    external.write_text(config_text, encoding="utf-8")

    result = _invoke_json(str(target), "--config", str(external))

    assert result.exit_code == 2
    assert expected in result.output


def test_ignore_rule_limits_are_enforced():
    with pytest.raises(ValueError, match="512"):
        IgnoreRule("a" * 513)
    with pytest.raises(ValueError, match="at most"):
        Config(ignore=[IgnoreRule(str(index)) for index in range(MAX_IGNORE_RULES + 1)])


def test_catastrophic_ignore_regex_times_out():
    rule = IgnoreRule(r"(a+)+$")
    with pytest.raises(ValueError, match="25 ms"):
        rule.matches("a" * 200_000 + "!")
