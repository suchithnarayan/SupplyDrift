"""
MCP server config scanner.

`.mcp.json` / `mcp.json` files declare external Model Context Protocol servers
that the AI client (Claude Code, Cursor, VS Code, etc.) launches. A typical
entry looks like:

    {
      "mcpServers": {
        "filesystem": {
          "command": "npx",
          "args": ["-y", "@modelcontextprotocol/server-filesystem@latest", "/path"]
        }
      }
    }

These behave like CI-context shadow installs: every invocation can pull a
new package version. Mutable version specifiers (`@latest`, `@alpha`,
`@next`) make the risk worse.

This scanner runs against the `mcp_config` file_type defined in discovery.py.
"""
from __future__ import annotations

import json
import re
from typing import Any

from github_inventory.discovery import FileTarget
from github_inventory.models import Category, Finding, Severity
from github_inventory.scanners.base import BaseScanner, PatternRule

_MUTABLE_SPEC_RE = re.compile(r"@(?:latest|alpha|beta|next|canary|nightly|edge)\b", re.IGNORECASE)
_MUTABLE_IMAGE_TAGS = frozenset({"latest", "alpha", "beta", "next", "canary", "nightly", "edge"})
_RUNNERS = {"npx", "pnpx", "uvx", "bunx", "pnpm", "dnx"}
_SAFE_COMMANDS = {"sh", "bash", "zsh", "python", "python3", "node", "deno"}
_DOCKER_VALUE_FLAGS = {
    "--add-host", "--annotation", "--attach", "--blkio-weight", "--cap-add",
    "--cap-drop", "--cgroup-parent", "--cidfile", "--cpuset-cpus", "--cpuset-mems",
    "--device", "--device-cgroup-rule", "--device-read-bps", "--device-read-iops",
    "--device-write-bps", "--device-write-iops", "--dns", "--dns-option",
    "--dns-search", "--entrypoint", "--env", "--env-file", "--expose", "--gpus",
    "--group-add", "--health-cmd", "--health-interval", "--health-retries",
    "--health-start-period", "--health-timeout", "--hostname", "--ip", "--ip6",
    "--ipc", "--isolation", "--kernel-memory", "--label", "--label-file", "--link",
    "--link-local-ip", "--log-driver", "--log-opt", "--mac-address", "--memory",
    "--memory-reservation", "--memory-swap", "--memory-swappiness", "--mount",
    "--name", "--network", "--network-alias", "--oom-score-adj", "--pid",
    "--platform", "--publish", "--pull", "--restart", "--runtime", "--security-opt",
    "--shm-size", "--stop-signal", "--stop-timeout", "--storage-opt", "--sysctl",
    "--tmpfs", "--ulimit", "--user", "--userns", "--volume", "--volumes-from",
    "--workdir",
}
_DOCKER_SHORT_VALUE_FLAGS = frozenset({"a", "e", "h", "l", "m", "p", "u", "v", "w"})


class MCPServerScanner(BaseScanner):
    name = "mcp-servers"

    def scan_file_content(self, target: FileTarget, content: str, lines: list[str]) -> list[Finding]:
        if target.file_type != "mcp_config":
            return []

        scan_content = content
        try:
            data = json.loads(scan_content)
        except json.JSONDecodeError:
            scan_content = _strip_jsonc_comments(content)
            try:
                data = json.loads(scan_content)
            except json.JSONDecodeError:
                findings = super().scan_file_content(
                    target,
                    scan_content,
                    scan_content.splitlines(),
                )
                return _filter_mcp_fixture_placeholder_findings(target, findings)

        objects = _explicit_mcp_server_objects(data)
        if not objects and _is_known_mcp_config_path(target.rel_path):
            objects = _walk_objects(data)

        findings: list[Finding] = []
        for obj in objects:
            url = _first_string(obj, ("url", "endpoint", "sseUrl", "httpUrl"))
            if url and url.startswith(("http://", "https://")):
                findings.append(_finding(
                    target=target,
                    content=scan_content,
                    category=Category.MCP_SERVER,
                    severity=Severity.HIGH,
                    pattern_id="mcp-server-remote-url",
                    dep=url,
                    matched=url,
                    description=f"MCP server uses remote endpoint: {url}",
                ))

            command = obj.get("command")
            if not isinstance(command, str):
                continue
            command_name = command.split()[0].lower()
            args = [arg for arg in obj.get("args", []) if isinstance(arg, str)]

            if command_name == "docker":
                dep = _docker_run_image_dep(args)
                if dep:
                    severity = Severity.CRITICAL if _is_mutable_image_dep(dep) else Severity.HIGH
                    findings.append(_finding(
                        target=target,
                        content=scan_content,
                        category=Category.MCP_SERVER,
                        severity=severity,
                        pattern_id="mcp-server-docker-image",
                        dep=dep,
                        matched=dep,
                        description=f"MCP server runs Docker image on launch: {dep}",
                    ))
                    continue

            if command_name == "npm":
                dep = _npm_exec_dep(args)
                if dep:
                    findings.append(_finding(
                        target=target,
                        content=scan_content,
                        category=Category.MCP_SERVER,
                        severity=Severity.HIGH,
                        pattern_id="mcp-server-runner-package",
                        dep=dep,
                        matched=dep,
                        description=f"MCP server runs package/source on every launch: {dep}",
                    ))
                continue

            if command_name in _RUNNERS:
                dep = _runner_dep(command_name, args)
                if dep:
                    severity = Severity.CRITICAL if _MUTABLE_SPEC_RE.search(dep) else Severity.HIGH
                    findings.append(_finding(
                        target=target,
                        content=scan_content,
                        category=Category.MCP_SERVER,
                        severity=severity,
                        pattern_id="mcp-server-runner-package",
                        dep=dep,
                        matched=dep,
                        description=f"MCP server runs package/source on every launch: {dep}",
                    ))
                continue

            if command_name not in _SAFE_COMMANDS:
                findings.append(_finding(
                    target=target,
                    content=scan_content,
                    category=Category.MCP_SERVER,
                    severity=Severity.MEDIUM,
                    pattern_id="mcp-server-arbitrary-command",
                    dep=command,
                    matched=command,
                    description=f"MCP server runs custom command: {command}",
                ))

        return _filter_mcp_fixture_placeholder_findings(target, _dedupe(findings))

    def register_rules(self) -> None:
        # A package runner command inside an MCP server "args" array
        # that executes a versioned package reference. Captures `@<version>`.
        self.add_rule(PatternRule(
            pattern_id="mcp-server-npx-package",
            regex=re.compile(
                r'"(?:npx|pnpx|uvx|bunx|pnpm|dnx)"[^}]*?"args"\s*:\s*\[[^\]]*?'
                r'"(?:-y|--yes)?\s*"?,?\s*"(?P<dep>(?:@[\w.-]+/)?[\w][\w.-]*(?:@[\w.+\-]+)?)"',
                re.IGNORECASE | re.DOTALL,
            ),
            severity=Severity.HIGH,
            description_template="MCP server runs package on every launch: {dep}",
            category=Category.MCP_SERVER,
            file_types=["mcp_config"],
            multiline=True,
            escalate_when=[
                (re.compile(r"@(?:latest|alpha|beta|next|canary|nightly|edge)\b", re.IGNORECASE), Severity.CRITICAL),
            ],
        ))

        # MCP server with a remote URL (HTTP/SSE transport) — the server
        # itself is hosted externally; remote code-execution risk is even
        # higher than launching a local package.
        self.add_rule(PatternRule(
            pattern_id="mcp-server-remote-url",
            regex=re.compile(
                r'"(?:url|endpoint|sseUrl|httpUrl)"\s*:\s*"(?P<dep>https?://\S+?)"',
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="MCP server uses remote endpoint: {dep}",
            category=Category.MCP_SERVER,
            file_types=["mcp_config"],
        ))

        # Generic command field with a non-stdlib, non-package-runner executable.
        # The npx/uvx/bunx/pnpm cases are already covered by the more specific
        # `mcp-server-npx-package` rule above (with @-tag escalation); skip them
        # here to avoid double-firing.
        self.add_rule(PatternRule(
            pattern_id="mcp-server-arbitrary-command",
            regex=re.compile(
                r'"command"\s*:\s*"'
                r'(?P<dep>(?!sh\b|bash\b|zsh\b|python3?\b|node\b|deno\b'
                r'|npx\b|pnpx\b|uvx\b|bunx\b|pnpm\b|dnx\b)[^"]+)"',
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            description_template="MCP server runs custom command: {dep}",
            category=Category.MCP_SERVER,
            file_types=["mcp_config"],
        ))


def _walk_objects(value: Any) -> list[dict[str, Any]]:
    objects: list[dict[str, Any]] = []
    if isinstance(value, dict):
        objects.append(value)
        for child in value.values():
            objects.extend(_walk_objects(child))
    elif isinstance(value, list):
        for child in value:
            objects.extend(_walk_objects(child))
    return objects


def _explicit_mcp_server_objects(value: Any) -> list[dict[str, Any]]:
    objects: list[dict[str, Any]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "mcpServers":
                if isinstance(child, dict):
                    objects.extend(v for v in child.values() if isinstance(v, dict))
                elif isinstance(child, list):
                    objects.extend(v for v in child if isinstance(v, dict))
            else:
                objects.extend(_explicit_mcp_server_objects(child))
    elif isinstance(value, list):
        for child in value:
            objects.extend(_explicit_mcp_server_objects(child))
    return objects


def _is_known_mcp_config_path(rel_path: str) -> bool:
    rel = rel_path.replace("\\", "/").lower()
    name = rel.rsplit("/", 1)[-1]
    return (
        name in {".mcp.json", "mcp.json"}
        or rel.endswith("/.mcp/mcp.json")
        or rel.endswith("/.cursor/mcp.json")
        or rel.endswith("/.vscode/mcp.json")
    )


def _strip_jsonc_comments(content: str) -> str:
    chars = list(content)
    in_string = False
    escape = False
    i = 0
    while i < len(chars):
        ch = chars[i]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            i += 1
            continue
        if ch == "/" and i + 1 < len(chars) and chars[i + 1] == "/":
            chars[i] = chars[i + 1] = " "
            i += 2
            while i < len(chars) and chars[i] not in "\r\n":
                chars[i] = " "
                i += 1
            continue
        if ch == "/" and i + 1 < len(chars) and chars[i + 1] == "*":
            chars[i] = chars[i + 1] = " "
            i += 2
            while i + 1 < len(chars):
                if chars[i] == "*" and chars[i + 1] == "/":
                    chars[i] = chars[i + 1] = " "
                    i += 2
                    break
                if chars[i] not in "\r\n":
                    chars[i] = " "
                i += 1
            continue
        i += 1
    return _strip_jsonc_trailing_commas("".join(chars))


def _strip_jsonc_trailing_commas(content: str) -> str:
    chars = list(content)
    in_string = False
    escape = False
    i = 0
    while i < len(chars):
        ch = chars[i]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            i += 1
            continue
        if ch == ",":
            j = i + 1
            while j < len(chars) and chars[j].isspace():
                j += 1
            if j < len(chars) and chars[j] in "]}":
                chars[i] = " "
        i += 1
    return "".join(chars)


def _first_string(obj: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = obj.get(key)
        if isinstance(value, str):
            return value
    return None


def _runner_dep(command: str, args: list[str]) -> str | None:
    if command == "pnpm":
        args = args[1:] if args and args[0] == "dlx" else args

    if command == "uvx":
        for i, arg in enumerate(args):
            if arg == "--from" and i + 1 < len(args):
                return args[i + 1]
            if arg.startswith("--from="):
                return arg.split("=", 1)[1]

    skip_value_for = {"--package", "-p", "--registry", "--cache", "--prefix"}
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in {"-y", "--yes"}:
            i += 1
            continue
        if arg in skip_value_for:
            i += 2
            continue
        if arg.startswith("-"):
            i += 1
            continue
        return arg
    return None


def _npm_exec_dep(args: list[str]) -> str | None:
    if not args or args[0] not in {"exec", "x"}:
        return None
    args = args[1:]
    if any(arg in {"--no", "--no-install"} or arg == "--yes=false" for arg in args):
        return None

    dep_from_package_option = _npm_package_option_dep(args)
    if dep_from_package_option:
        return dep_from_package_option

    return _npm_exec_positional_dep(args)


def _npm_package_option_dep(args: list[str]) -> str | None:
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            return None
        if arg in {"--package", "-p"}:
            return args[i + 1] if i + 1 < len(args) else None
        if arg.startswith("--package="):
            return arg.split("=", 1)[1]
        i += 1
    return None


def _npm_exec_positional_dep(args: list[str]) -> str | None:
    skip_value_for = {"--call", "-c", "--registry", "--cache", "--prefix"}
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            i += 1
            continue
        if arg in {"-y", "--yes"}:
            i += 1
            continue
        if arg in skip_value_for:
            i += 2
            continue
        if arg.startswith("-"):
            i += 1
            continue
        if arg.startswith((".", "/", "$")):
            return None
        return arg
    return None


def _docker_run_image_dep(args: list[str]) -> str | None:
    if not args or args[0] != "run":
        return None

    i = 1
    while i < len(args):
        arg = args[i]
        if not arg:
            i += 1
            continue
        next_i = _skip_docker_run_option(args, i)
        if next_i != i:
            i = next_i
            continue
        if arg.startswith((".", "/", "$")):
            return None
        if arg.startswith("-"):
            i += 1
            continue
        return arg.strip("\"'")
    return None


def _skip_docker_run_option(args: list[str], index: int) -> int:
    arg = args[index]
    if arg == "--":
        return index + 1

    if arg.startswith("--"):
        name = arg.split("=", 1)[0]
        if name in _DOCKER_VALUE_FLAGS:
            return index + 1 if "=" in arg else min(index + 2, len(args))
        return index + 1

    if arg.startswith("-") and len(arg) > 1:
        if len(arg) == 2 and arg[1] in _DOCKER_SHORT_VALUE_FLAGS:
            return min(index + 2, len(args))
        if len(arg) > 2 and arg[1] in _DOCKER_SHORT_VALUE_FLAGS:
            return index + 1
        return index + 1

    return index


def _is_mutable_image_dep(dep: str) -> bool:
    if "@sha256:" in dep:
        return False
    image_name = dep.rsplit("/", 1)[-1]
    if ":" not in image_name:
        return True
    tag = image_name.rsplit(":", 1)[1].lower()
    return tag in _MUTABLE_IMAGE_TAGS


def _finding(
    *,
    target: FileTarget,
    content: str,
    category: Category,
    severity: Severity,
    pattern_id: str,
    dep: str,
    matched: str,
    description: str,
) -> Finding:
    line_number = _line_number(content, matched)
    return Finding(
        file_path=target.rel_path,
        line_number=line_number,
        category=category,
        severity=severity,
        pattern_id=pattern_id,
        matched_text=matched[:200],
        extracted_dep=dep[:200],
        description=description,
        scanner_name=MCPServerScanner.name,
    )


def _line_number(content: str, token: str) -> int:
    escaped = json.dumps(token)
    idx = content.find(escaped)
    if idx == -1:
        idx = content.find(token)
    return content[:idx].count("\n") + 1 if idx >= 0 else 1


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, int, str, str]] = set()
    deduped: list[Finding] = []
    for finding in findings:
        key = (finding.file_path, finding.line_number, finding.pattern_id, finding.extracted_dep)
        if key not in seen:
            seen.add(key)
            deduped.append(finding)
    return deduped


def _filter_mcp_fixture_placeholder_findings(
    target: FileTarget,
    findings: list[Finding],
) -> list[Finding]:
    if not _is_mcp_fixture_path(target.rel_path):
        return findings
    return [
        finding for finding in findings
        if not _is_mcp_fixture_placeholder_finding(finding)
    ]


def _is_mcp_fixture_path(rel_path: str) -> bool:
    parts = {part.lower() for part in rel_path.replace("\\", "/").split("/")}
    return bool(parts & {"fixtures", "fixture", "__fixtures__", "testdata"})


def _is_mcp_fixture_placeholder_finding(finding: Finding) -> bool:
    if finding.pattern_id == "mcp-server-remote-url":
        return _is_reserved_invalid_url(finding.extracted_dep)
    if finding.pattern_id == "mcp-server-runner-package":
        return finding.extracted_dep in {"some-pkg", "stdio-pkg"}
    return False


def _is_reserved_invalid_url(value: str) -> bool:
    return bool(re.match(r"https?://[^/\s:]+\.invalid(?::\d+)?(?:/|$)", value, re.IGNORECASE))
