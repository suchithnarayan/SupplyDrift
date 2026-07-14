"""Category 1: curl|bash, wget|sh, eval $(curl), and variants."""
from __future__ import annotations

import ast
import base64
import binascii
import json
import re
import shlex

from github_inventory.discovery import FileTarget
from github_inventory.models import Category, Finding, Severity
from github_inventory.scanners.base import BaseScanner, PatternRule, is_placeholder_url_dependency
from github_inventory.scanners.source_shell import (
    iter_javascript_shell_commands,
    iter_python_shell_commands,
    parse_python_source,
)

_FT = ["ci", "script", "build", "dockerfile", "github_action", "agent_instruction", "package_config"]
_URL_TOKEN = r"""https?://[^\s'"`)|<>]+"""
_PIPELINE_URL_TOKEN = r"""https?://(?:(?:\$\([^)\n]*\))|[^\s'"`)|<>\\])+"""
_POWERSHELL_URI_TOKEN = r"""(?:https?://[^\s'"|]+|[A-Za-z0-9][\w.-]+\.[A-Za-z]{2,}/[^\s'"|]+)"""
_SHELL_PIPE_TARGET = (
    r"(?:sudo(?:\s+(?:-[A-Za-z]+|--[A-Za-z][\w-]*))*\s+)?"
    r"(?:env\s+(?:[A-Za-z_][A-Za-z0-9_]*=\S+\s+)*)?"
    r"(?:bash|sh|zsh|dash)\b"
)
_INTERPRETER_PIPE_TARGET = r"(?:python3?(?:\.\d+)?|node|deno|perl|ruby|php|tclsh)\b"
_MARKDOWN_DOC_EXTENSIONS = frozenset({".md", ".mdx"})
_ORDINARY_MARKDOWN_DOC_NAMES = frozenset({
    "README.md",
    "INSTALL.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "PUBLISHING.md",
    "DEVELOPER.md",
    "MAC-README.md",
    "MOBILE-README.md",
    "WINDOWS-README.md",
})
_AGENT_CONTROL_DOC_NAMES = frozenset({"AGENTS.md", "CLAUDE.md", "CODEX.md", "SKILL.md"})
_AGENT_CONTROL_DOC_DIRS = frozenset({".agents", ".claude", ".codex", ".cursor"})
_SCRIPT_MARKDOWN_COMMAND_RE = re.compile(
    r"\b(?:"
    r"curl|wget|bash|sh|zsh|dash|source|eval|"
    r"Invoke-RestMethod|Invoke-WebRequest|irm|iwr|Invoke-Expression|iex|"
    r"python3?(?:\.\d+)?|node|deno|perl|ruby|php|tclsh"
    r")\b",
    re.IGNORECASE,
)
_RESERVED_EXAMPLE_URL_RE = re.compile(
    r"^https?://example\.(?:com|org|net)(?:[/:?#]|$)",
    re.IGNORECASE,
)
_DEVCONTAINER_SCRIPT_COMMAND_RE = re.compile(
    r'"(?:initializeCommand|onCreateCommand|updateContentCommand|postCreateCommand|'
    r'postStartCommand|postAttachCommand|postStopCommand)"\s*:\s*(?P<command>"(?:\\.|[^"\\])*")',
)


class ScriptInstallationScanner(BaseScanner):
    name = "script-installations"

    def scan_file(self, target: FileTarget) -> list[Finding]:
        applicable = [r for r in self._rules if "*" in r.file_types or target.file_type in r.file_types]
        if not applicable and target.file_type not in {"source_code", "devcontainer"}:
            return []
        try:
            content = target.path.read_text(errors="replace")
        except OSError:
            return []
        return self.scan_file_content(target, content, content.splitlines())

    def scan_file_content(self, target: FileTarget, content: str, lines: list[str]) -> list[Finding]:
        findings = super().scan_file_content(target, content, lines)
        findings.extend(_scan_source_shell_script_installations(target, content, lines, findings))
        findings.extend(_scan_devcontainer_script_install_commands(target, lines, findings))
        findings.extend(_scan_python_urlretrieve_script_execution(target, content, lines, findings))
        findings.extend(_scan_base64_decoded_shell_execution(target, lines, findings))
        findings.extend(_scan_powershell_iex_variable_urls(target, lines, findings))
        findings.extend(_scan_powershell_downloaded_script_variables(target, lines, findings))
        findings.extend(_scan_powershell_downloaded_scriptblock_execution(target, lines, findings))
        findings.extend(_scan_batch_downloaded_script_execution(target, lines, findings))
        findings.extend(_scan_shell_downloaded_script_execution(target, lines, findings))
        findings = [
            finding for finding in findings
            if not (
                finding.pattern_id == "remote-interpreter-pipe"
                and _is_metadata_interpreter_pipe(finding.matched_text, finding.extracted_dep)
            )
        ]
        literal_curl_pipe_lines = {
            finding.line_number for finding in findings
            if finding.pattern_id in {"curl-pipe-bash", "curl-chained-pipe-shell"}
        }
        findings = [
            finding for finding in findings
            if not (
                finding.pattern_id == "curl-var-pipe-bash"
                and finding.line_number in literal_curl_pipe_lines
            )
        ]
        findings = [
            finding for finding in findings
            if not _is_non_control_markdown_script_install_example(target, finding, lines)
            and not _is_non_executable_package_config_script_install(target, finding, lines)
            and not _is_powershell_block_comment_line(target, lines, finding.line_number)
            and not _is_printed_powershell_webclient_downloadstring_hint(finding)
            and not is_placeholder_url_dependency(finding.extracted_dep)
            and not _is_reserved_example_url_in_agent_instruction(target, finding)
        ]
        return _dedupe_findings_by_file_dependency(findings)

    def register_rules(self) -> None:
        # curl ... URL ... | bash/sh/zsh
        self.add_rule(PatternRule(
            pattern_id="curl-pipe-bash",
            regex=re.compile(
                r"curl\s+[^|\n]*?(?P<dep>" + _URL_TOKEN + r")[^|\n]*?\|\s*" + _SHELL_PIPE_TARGET,
                re.IGNORECASE,
            ),
            severity=Severity.CRITICAL,
            description_template="Remote script piped directly to shell: {dep}",
            category=Category.SCRIPT_INSTALLATION,
            file_types=_FT,
        ))

        # wget ... URL | bash/sh
        self.add_rule(PatternRule(
            pattern_id="wget-pipe-bash",
            regex=re.compile(
                r"wget\s+[^|\n]*?(?P<dep>" + _URL_TOKEN + r")[^|\n]*?\|\s*" + _SHELL_PIPE_TARGET,
                re.IGNORECASE,
            ),
            severity=Severity.CRITICAL,
            description_template="Remote script piped to shell via wget: {dep}",
            category=Category.SCRIPT_INSTALLATION,
            file_types=_FT,
        ))

        # curl URL \
        #   | sed ... \
        #   | sh
        #
        # Installers often split long pipelines over shell continuation lines,
        # sometimes filtering the installer stream before executing it.
        self.add_rule(PatternRule(
            pattern_id="remote-multiline-pipe-shell",
            regex=re.compile(
                r"\b(?:curl|wget)\b[^\n]*?(?P<dep>" + _PIPELINE_URL_TOKEN + r")[^\n]*?\\\s*\n"
                r"(?:\s*\|\s*(?!(?:sha\d*sum|shasum|md5sum|gpg|openssl)\b)[^\n]*?\\\s*\n){0,4}"
                r"\s*\|\s*" + _SHELL_PIPE_TARGET,
                re.IGNORECASE,
            ),
            severity=Severity.CRITICAL,
            description_template="Remote script pipeline split over continuation lines executes in shell: {dep}",
            category=Category.SCRIPT_INSTALLATION,
            file_types=_FT,
            multiline=True,
        ))

        # bash <(curl URL) or sh <(curl URL)
        self.add_rule(PatternRule(
            pattern_id="bash-process-substitution",
            regex=re.compile(
                r"(?:bash|sh|zsh)\s+<\(\s*(?:curl|wget)\s+[^)]*?(?P<dep>" + _URL_TOKEN + r")",
                re.IGNORECASE,
            ),
            severity=Severity.CRITICAL,
            description_template="Remote script executed via process substitution: {dep}",
            category=Category.SCRIPT_INSTALLATION,
            file_types=_FT,
        ))

        # source <(curl URL) or . <(curl URL)
        self.add_rule(PatternRule(
            pattern_id="source-curl",
            regex=re.compile(
                r"(?:source|\.)\s+<\(\s*(?:curl|wget)\s+[^)]*?(?P<dep>" + _URL_TOKEN + r")",
                re.IGNORECASE,
            ),
            severity=Severity.CRITICAL,
            description_template="Remote script sourced into current shell: {dep}",
            category=Category.SCRIPT_INSTALLATION,
            file_types=_FT,
        ))

        # eval "$(curl URL)" or eval $(curl URL)
        self.add_rule(PatternRule(
            pattern_id="eval-curl",
            regex=re.compile(
                r"eval\s+[\"']?\$\(\s*(?:curl|wget)\s+[^)]*?(?P<dep>" + _URL_TOKEN + r")",
                re.IGNORECASE,
            ),
            severity=Severity.CRITICAL,
            description_template="Remote script eval'd into shell: {dep}",
            category=Category.SCRIPT_INSTALLATION,
            file_types=_FT,
        ))

        # curl $VAR | bash — variable-substituted URL piped to shell.
        # The URL itself is hidden in the variable; we emit the variable name
        # as the dep so the user knows where to look.
        self.add_rule(PatternRule(
            pattern_id="curl-var-pipe-bash",
            regex=re.compile(
                r"curl\s+[^|\n]*?(?P<dep>\$\{?[A-Za-z_][A-Za-z0-9_]*\}?)"
                r"[^|\n]*?\|[^|\n]*?(?:sudo\s+)?(?:bash|sh|zsh|dash)\b",
            ),
            severity=Severity.CRITICAL,
            description_template="Remote script piped to shell via variable URL: {dep}",
            category=Category.SCRIPT_INSTALLATION,
            file_types=_FT,
        ))

        # Alias-like helper commands that pipe a URL to a shell.
        # Real scripts often hide curl/wget behind `get` or `fetch`; even
        # without resolving the alias, piping an HTTPS response to a shell is
        # enough signal to report the execution.
        self.add_rule(PatternRule(
            pattern_id="alias-url-pipe-shell",
            regex=re.compile(
                r"(?:^|\bRUN\s+|[;&|]\s*)(?:get|fetch|download)\s+[^|\n]*?(?P<dep>" + _URL_TOKEN + r")"
                r"[^|\n]*?\|\s*" + _SHELL_PIPE_TARGET,
                re.IGNORECASE,
            ),
            severity=Severity.CRITICAL,
            description_template="Remote script piped to shell via helper/alias command: {dep}",
            category=Category.SCRIPT_INSTALLATION,
            file_types=_FT,
        ))

        # curl URL > /tmp/script && bash /tmp/script
        self.add_rule(PatternRule(
            pattern_id="curl-download-then-execute",
            regex=re.compile(
                r"curl\s+[^>\n]*?(?P<dep>" + _URL_TOKEN + r")[^>\n]*?>\s*(?P<tmp>\S+)"
                r"[^\n]*(?:&&|;)\s*(?:sudo\s+)?(?:bash|sh|zsh|dash)\s+(?P=tmp)\b",
                re.IGNORECASE,
            ),
            severity=Severity.CRITICAL,
            description_template="Remote script downloaded then executed by shell: {dep}",
            category=Category.SCRIPT_INSTALLATION,
            file_types=_FT,
        ))

        # bash -c / sh -c with $(curl ...) or `curl ...` subshell substitution.
        # Catches: bash -c "$(curl ...)", sh -c "`curl ...`"
        self.add_rule(PatternRule(
            pattern_id="shell-c-subshell-curl",
            regex=re.compile(
                r"(?:bash|sh|zsh|dash)\s+-c\s+[\"'][^\"']*?(?:\$\(|`)\s*"
                r"(?:curl|wget)\s+[^)\"'`]*?(?P<dep>" + _URL_TOKEN + r")",
                re.IGNORECASE,
            ),
            severity=Severity.CRITICAL,
            description_template="Remote script executed via shell -c subshell: {dep}",
            category=Category.SCRIPT_INSTALLATION,
            file_types=_FT,
        ))

        # Inline interpreter executing remote-fetched code:
        # `python -c "$(curl ...)"`, `node -e "$(curl ...)"`, etc.
        # Same RCE risk as `bash -c "$(curl ...)"` but slips past the
        # shell-only patterns above.
        self.add_rule(PatternRule(
            pattern_id="inline-interpreter-curl",
            regex=re.compile(
                r"\b(?:python3?|node|deno|perl|ruby|php|tclsh)\s+-(?:c|e)\s+"
                r"['\"]?\$\(\s*(?:curl|wget|fetch)\s+[^)]*?(?P<dep>" + _URL_TOKEN + r")",
                re.IGNORECASE,
            ),
            severity=Severity.CRITICAL,
            description_template="Inline interpreter executes remote-fetched code: {dep}",
            category=Category.SCRIPT_INSTALLATION,
            file_types=_FT,
        ))

        # curl/wget URL | node/python/ruby/etc. executes remote code in an
        # interpreter even though no shell is involved. Post-filter JSON/API
        # parsing pipes in scan_file_content; those are metadata reads.
        self.add_rule(PatternRule(
            pattern_id="remote-interpreter-pipe",
            regex=re.compile(
                r"\b(?:curl|wget)\b[^|\n]*?(?P<dep>" + _URL_TOKEN + r")[^|\n]*?"
                r"\|\s*" + _INTERPRETER_PIPE_TARGET,
                re.IGNORECASE,
            ),
            severity=Severity.CRITICAL,
            description_template="Remote response piped directly to interpreter: {dep}",
            category=Category.SCRIPT_INSTALLATION,
            file_types=_FT,
        ))

        # PowerShell equivalent of curl|bash:
        # `irm https://example/install.ps1 | iex`,
        # `irm example.com/install.ps1 | iex`, or
        # `Invoke-WebRequest -Uri ... | Invoke-Expression`.
        self.add_rule(PatternRule(
            pattern_id="powershell-web-pipe-iex",
            regex=re.compile(
                r"\b(?:Invoke-RestMethod|Invoke-WebRequest|irm|iwr)\b"
                r"[^|\n]*?(?:-Uri\s+)?['\"]?(?P<dep>" + _POWERSHELL_URI_TOKEN + r")['\"]?"
                r"[^|\n]*?\|\s*(?:Invoke-Expression|iex)\b",
                re.IGNORECASE,
            ),
            severity=Severity.CRITICAL,
            description_template="Remote PowerShell script piped to Invoke-Expression: {dep}",
            category=Category.SCRIPT_INSTALLATION,
            file_types=_FT,
        ))

        self.add_rule(PatternRule(
            pattern_id="powershell-iex-web-subexpression",
            regex=re.compile(
                r"\b(?:Invoke-Expression|iex)\s*\(\s*"
                r"(?:Invoke-RestMethod|Invoke-WebRequest|irm|iwr)\b"
                r"[^)\n]*?(?:-Uri\s+)?['\"]?(?P<dep>https?://[^\s'\"()]+)['\"]?"
                r"[^)]*\)",
                re.IGNORECASE,
            ),
            severity=Severity.CRITICAL,
            description_template="Remote PowerShell script executed via Invoke-Expression: {dep}",
            category=Category.SCRIPT_INSTALLATION,
            file_types=_FT,
        ))

        self.add_rule(PatternRule(
            pattern_id="powershell-webclient-downloadstring-iex",
            regex=re.compile(
                r"\b(?:Invoke-Expression|iex)\b[^\n]*?"
                r"(?:"
                r"\(\s*New-Object\s+(?:-TypeName\s+)?(?:System\.)?Net\.WebClient\s*\)"
                r"|\[(?:System\.)?Net\.WebClient\]::new\s*\(\s*\)"
                r")\s*\.\s*DownloadString\s*\(\s*['\"](?P<dep>https?://[^'\"\s)]+)['\"]",
                re.IGNORECASE,
            ),
            severity=Severity.CRITICAL,
            description_template="Remote PowerShell script downloaded with WebClient.DownloadString and executed: {dep}",
            category=Category.SCRIPT_INSTALLATION,
            file_types=_FT,
        ))

        self.add_rule(PatternRule(
            pattern_id="powershell-iex-web-substitution",
            regex=re.compile(
                r"\b(?:Invoke-Expression|iex)\s+['\"][^'\"]*?\$\(\s*"
                r"(?:Invoke-RestMethod|Invoke-WebRequest|irm|iwr)\b"
                r"[^)'\"]*?(?:-Uri\s+)?['\"]?(?P<dep>https?://[^\s'\"()]+)['\"]?"
                r"[^)]*\)",
                re.IGNORECASE,
            ),
            severity=Severity.CRITICAL,
            description_template="Remote PowerShell script executed via Invoke-Expression substitution: {dep}",
            category=Category.SCRIPT_INSTALLATION,
            file_types=_FT,
        ))

        self.add_rule(PatternRule(
            pattern_id="powershell-scriptblock-web-execution",
            regex=re.compile(
                r"(?:^|[;&|]\s*)[&.]\s*\(\s*\[scriptblock\]::Create\s*\(\s*\(\s*"
                r"(?:Invoke-RestMethod|Invoke-WebRequest|irm|iwr)\b"
                r"[^)\n]*?(?:-Uri\s+)?['\"]?(?P<dep>https?://[^\s'\"()]+)['\"]?"
                r"[^)]*\)\s*\)",
                re.IGNORECASE,
            ),
            severity=Severity.CRITICAL,
            description_template="Remote PowerShell script executed via ScriptBlock::Create: {dep}",
            category=Category.SCRIPT_INSTALLATION,
            file_types=_FT,
        ))

        # Chained-pipe download → bash (gunzip|tar|bash, tee|sh, etc.)
        # Catches: curl URL | gunzip | bash, curl URL | tee file | sh
        self.add_rule(PatternRule(
            pattern_id="curl-chained-pipe-shell",
            regex=re.compile(
                r"(?:curl|wget)\s+[^|\n]*?(?P<dep>" + _URL_TOKEN + r")[^|\n]*?"
                r"(?:\|\s*[a-zA-Z][\w./ -]*?){1,4}\|\s*(?:sudo\s+)?(?:bash|sh|zsh|dash)\b",
                re.IGNORECASE,
            ),
            severity=Severity.CRITICAL,
            description_template="Remote script piped through filters to shell: {dep}",
            category=Category.SCRIPT_INSTALLATION,
            file_types=_FT,
        ))


_POWERSHELL_URL_ASSIGN_RE = re.compile(
    r"(?P<var>\$[A-Za-z_][A-Za-z0-9_]*)\s*=\s*['\"](?P<url>https?://[^'\"]+)['\"]",
    re.IGNORECASE,
)
_POWERSHELL_IEX_WEB_VAR_RE = re.compile(
    r"\b(?:Invoke-Expression|iex)\b[^\n]*?\$\(\s*"
    r"(?:Invoke-RestMethod|Invoke-WebRequest|irm|iwr)\b"
    r"[^)]*?(?P<var>\$[A-Za-z_][A-Za-z0-9_]*)\b",
    re.IGNORECASE,
)
_POWERSHELL_WEB_DOWNLOAD_VAR_RE = re.compile(
    r"\b(?:Invoke-WebRequest|iwr)\b(?P<body>[^\n]*?)"
    r"(?:-OutFile|-o)\s+(?P<out>\$[A-Za-z_][A-Za-z0-9_]*)\b",
    re.IGNORECASE,
)
_POWERSHELL_WEB_DOWNLOAD_LITERAL_RE = re.compile(
    r"\b(?:Invoke-WebRequest|iwr)\b(?P<body>[^\n]*?)"
    r"(?:-OutFile|-o)\s+(?P<out>['\"]?[^'\"\s;|]+\.(?:ps1|psm1|psd1)['\"]?)",
    re.IGNORECASE,
)
_POWERSHELL_WEB_DOWNLOAD_ANY_OUT_RE = re.compile(
    r"\b(?:Invoke-WebRequest|iwr)\b(?P<body>[^\n]*?)"
    r"(?:-OutFile|-o)\s+(?P<out>\"[^\"]+\"|'[^']+'|[^\s;|]+)",
    re.IGNORECASE,
)
_POWERSHELL_WEBCLIENT_DOWNLOADFILE_RE = re.compile(
    r"\.DownloadFile\s*\(\s*(?P<src>[^,\n]+)\s*,\s*(?P<out>[^)\n]+?)\s*\)",
    re.IGNORECASE,
)
_POWERSHELL_COMPOSED_SCRIPT_URL_RE = re.compile(
    r"(?P<base>\$[A-Za-z_][A-Za-z0-9_]*)\s*\+\s*"
    r"['\"](?P<suffix>[^'\"]*\.(?:ps1|psm1|psd1|sh|bash|zsh|dash|py|cmd|bat|js|mjs|cjs))['\"]",
    re.IGNORECASE,
)
_POWERSHELL_SCRIPT_VAR_EXEC_RE = re.compile(
    r"^\s*(?:&|\.)\s*(?P<call_var>\$[A-Za-z_][A-Za-z0-9_]*)\b"
    r"|^\s*(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)\b[^\n]*?"
    r"(?:-File\s+)?(?P<file_var>\$[A-Za-z_][A-Za-z0-9_]*)\b"
    r"|^\s*(?:&\s*)?wsl(?:\.exe)?\b[^\n]*?(?:-e|--exec)\s+['\"]?(?P<wsl_var>\$[A-Za-z_][A-Za-z0-9_]*)\b"
    r"|^\s*(?:&\s*)?(?:bash|sh|zsh|dash)\b[^\n]*?['\"]?(?P<shell_var>\$[A-Za-z_][A-Za-z0-9_]*)\b",
    re.IGNORECASE,
)
_POWERSHELL_SCRIPT_LITERAL_EXEC_RE = re.compile(
    r"(?:^\s*|[;&|]\s*)['\"]?(?P<direct_path>\.[\\/][^'\"\s;|]+\.(?:ps1|psm1|psd1))['\"]?"
    r"|(?:^\s*|[;&|]\s*)(?:&|\.)\s*['\"]?(?P<call_path>[^'\"\s;|]+\.(?:ps1|psm1|psd1))['\"]?"
    r"|(?:^\s*|[;&|]\s*)(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)\b[^\n]*?"
    r"(?:-File\s+)?['\"]?(?P<file_path>[^'\"\s;|]+\.(?:ps1|psm1|psd1))['\"]?",
    re.IGNORECASE,
)
_POWERSHELL_LITERAL_URL_RE = re.compile(r"https?://[^'\"\s)]+", re.IGNORECASE)
_POWERSHELL_VAR_ALIAS_RE = re.compile(
    r"(?P<dst>\$[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?:['\"][^'\"]*)?(?P<src>\$[A-Za-z_][A-Za-z0-9_]*)\b",
    re.IGNORECASE,
)
_POWERSHELL_INVOKE_EXPRESSION_RE = re.compile(r"\b(?:Invoke-Expression|iex)\b", re.IGNORECASE)
_SHELL_URL_ASSIGN_RE = re.compile(
    r"(?:^|\s)(?:local\s+)?(?P<var>[A-Za-z_][A-Za-z0-9_]*)="
    r"['\"](?P<url>https?://[^'\"]+)['\"]",
    re.IGNORECASE,
)
_SHELL_ASSIGN_RE = re.compile(
    r"(?:^|\s)(?:local\s+)?(?P<var>[A-Za-z_][A-Za-z0-9_]*)="
    r"(?P<value>\"[^\"]*\"|'[^']*'|[^'\"\s;|&]+)",
)
_SHELL_DOWNLOAD_TARGET_TOKEN = (
    r"\\?['\"]?"
    r"(?:\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|[A-Za-z_./$-][\w./$-]*)"
    r"\\?['\"]?"
)
_SHELL_DOWNLOAD_REDIRECT_RE = re.compile(
    r"(?<!\d)>\s*(?P<out>" + _SHELL_DOWNLOAD_TARGET_TOKEN + r")"
)
_CURL_DOWNLOAD_OUTPUT_RE = re.compile(
    r"(?:--output(?:=|\s+)|(?:^|\s)-[A-Za-z]*o\s+)"
    r"(?P<out>" + _SHELL_DOWNLOAD_TARGET_TOKEN + r")"
)
_WGET_DOWNLOAD_OUTPUT_RE = re.compile(
    r"(?:--output-document(?:=|\s+)|(?:^|\s)-O\s+)"
    r"(?P<out>" + _SHELL_DOWNLOAD_TARGET_TOKEN + r")"
)
_PRINT_HELP_RE = re.compile(
    r"^\s*(?:echo|printf|Write-(?:Host|Warning|Output|Verbose|Error|Debug))\b",
    re.IGNORECASE,
)
_PYTHON_JSON_PIPE_RE = re.compile(
    r"\|\s*python3?(?:\.\d+)?\s+"
    r"(?:-m\s+json\.tool|-c\s+['\"][^'\"]*\bjson\b)",
    re.IGNORECASE,
)
_METADATA_URL_RE = re.compile(
    r"^https?://(?:api\.github\.com/|[^/\s]+/(?:api/)?(?:health|healthz|status|instances)(?:[/?#]|$))",
    re.IGNORECASE,
)
_BASE64_DECODE_RE = re.compile(r"\bbase64\s+(?:--decode|-d)\b", re.IGNORECASE)
_BASE64_LITERAL_RE = re.compile(r"['\"](?P<value>[A-Za-z0-9+/]{24,}={0,2})['\"]")
_REMOTE_SHELL_PAYLOAD_RE = re.compile(
    r"\b(?:curl|wget)\b[^\n|]*?(?P<url>https?://[^\s'\"`|]+)[^\n|]*?\|\s*"
    + _SHELL_PIPE_TARGET,
    re.IGNORECASE,
)
_PYTHON_BASE64_EXEC_RE = re.compile(
    r"\bpython3?\b[^\n]*(?:base64\.(?:b64decode|decodebytes)|b64decode)[^\n]*"
    r"(?:os\.system|subprocess\.(?:run|call|check_call|check_output|Popen)|exec|eval)"
    r"|"
    r"\bpython3?\b[^\n]*(?:os\.system|subprocess\.(?:run|call|check_call|check_output|Popen)|exec|eval)"
    r"[^\n]*(?:base64\.(?:b64decode|decodebytes)|b64decode)",
    re.IGNORECASE,
)
_PYTHON_SCRIPT_PATH_HINT_RE = re.compile(
    r"[.](?:py|sh|bash|zsh|dash|ps1|cmd|bat|js|mjs|cjs|rb|pl|php)(?:['\")\]}]|$)",
    re.IGNORECASE,
)
_SHELL_COMMAND_PREFIX = r"(?:^\s*(?:(?:RUN|if|then|do)\s+)?|(?:&&|\|\||[;&|])\s*)"
_SHELL_EXEC_ENV_PREFIX = (
    r"(?:sudo(?:\s+(?:-[A-Za-z]+|--[A-Za-z][\w-]*))*\s+)?"
    r"(?:env\s+(?:[A-Za-z_][A-Za-z0-9_]*=\S+\s+)*)?"
    r"(?:(?:[A-Za-z_][A-Za-z0-9_]*=\S+)\s+)*"
)
_SHELL_EXEC_RE = re.compile(
    _SHELL_COMMAND_PREFIX
    + _SHELL_EXEC_ENV_PREFIX
    + r"(?:bash|sh|zsh|dash)\b",
    re.IGNORECASE,
)
_SHELL_SOURCE_EXEC_RE = re.compile(
    _SHELL_COMMAND_PREFIX + r"(?:source|\.)\s+",
    re.IGNORECASE,
)


_SOURCE_SHELL_SCRIPT_INSTALL_PATTERNS = (
    (
        "curl-pipe-bash",
        re.compile(
            r"curl\s+[^|\n]*?(?P<dep>" + _URL_TOKEN + r")[^|\n]*?\|\s*" + _SHELL_PIPE_TARGET,
            re.IGNORECASE,
        ),
        "Remote script piped directly to shell",
    ),
    (
        "wget-pipe-bash",
        re.compile(
            r"wget\s+[^|\n]*?(?P<dep>" + _URL_TOKEN + r")[^|\n]*?\|\s*" + _SHELL_PIPE_TARGET,
            re.IGNORECASE,
        ),
        "Remote script piped to shell via wget",
    ),
    (
        "powershell-web-pipe-iex",
        re.compile(
            r"\b(?:Invoke-RestMethod|Invoke-WebRequest|irm|iwr)\b"
            r"[^|\n]*?(?:-Uri\s+)?['\"]?(?P<dep>" + _POWERSHELL_URI_TOKEN + r")['\"]?"
            r"[^|\n]*?\|\s*(?:Invoke-Expression|iex)\b",
            re.IGNORECASE,
        ),
        "Remote PowerShell script piped to Invoke-Expression",
    ),
)


def _scan_source_shell_script_installations(
    target: FileTarget,
    content: str,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    existing_keys = {
        (finding.line_number, finding.pattern_id, finding.extracted_dep)
        for finding in existing
    }
    added: list[Finding] = []
    commands = [
        *iter_python_shell_commands(target, content, lines),
        *iter_javascript_shell_commands(target, content, lines),
    ]
    for command in commands:
        for pattern_id, regex, description in _SOURCE_SHELL_SCRIPT_INSTALL_PATTERNS:
            match = regex.search(command.command)
            if not match:
                continue
            dep = match.group("dep")[:200]
            key = (command.line_number, pattern_id, dep)
            if key in existing_keys or is_placeholder_url_dependency(dep):
                continue
            added.append(Finding(
                file_path=target.rel_path,
                line_number=command.line_number,
                category=Category.SCRIPT_INSTALLATION,
                severity=Severity.CRITICAL,
                pattern_id=pattern_id,
                matched_text=command.command[:200],
                extracted_dep=dep,
                description=f"{description}: {dep}",
                scanner_name=ScriptInstallationScanner.name,
            ))
            existing_keys.add(key)
    return added


def _scan_devcontainer_script_install_commands(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type != "devcontainer":
        return []

    existing_keys = {
        (finding.line_number, finding.pattern_id, finding.extracted_dep)
        for finding in existing
    }
    added: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("//", "/*", "*")):
            continue
        match = _DEVCONTAINER_SCRIPT_COMMAND_RE.search(line)
        if not match:
            continue
        try:
            command = json.loads(match.group("command"))
        except json.JSONDecodeError:
            continue
        if not isinstance(command, str):
            continue
        for pattern_id, regex, description in _SOURCE_SHELL_SCRIPT_INSTALL_PATTERNS:
            command_match = regex.search(command)
            if not command_match:
                continue
            dep = command_match.group("dep")[:200]
            key = (line_number, pattern_id, dep)
            if key in existing_keys or is_placeholder_url_dependency(dep):
                continue
            added.append(Finding(
                file_path=target.rel_path,
                line_number=line_number,
                category=Category.SCRIPT_INSTALLATION,
                severity=Severity.CRITICAL,
                pattern_id=pattern_id,
                matched_text=command[:200],
                extracted_dep=dep,
                description=f"{description}: {dep}",
                scanner_name=ScriptInstallationScanner.name,
            ))
            existing_keys.add(key)
    return added


def _scan_python_urlretrieve_script_execution(
    target: FileTarget,
    content: str,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type != "source_code" or not target.rel_path.replace("\\", "/").lower().endswith(".py"):
        return []
    try:
        tree = parse_python_source(content)
    except SyntaxError:
        return []

    string_values = _collect_python_literal_string_assignments(tree)
    helpers = _collect_python_urlretrieve_script_helpers(tree)
    if not helpers:
        return []

    existing_keys = {
        (finding.line_number, finding.pattern_id, finding.extracted_dep)
        for finding in existing
    }
    added: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        helper = helpers.get(_python_call_function_name(node.func))
        if helper is None:
            continue
        param_name, param_index = helper
        arg = _python_call_arg(node, param_name, param_index)
        if arg is None:
            continue
        dep = _python_stringish_expr(arg, string_values)
        if not dep.startswith(("http://", "https://")) or is_placeholder_url_dependency(dep):
            continue
        line_number = getattr(node, "lineno", 1)
        key = (line_number, "python-urlretrieve-script-execution", dep)
        if key in existing_keys:
            continue
        source_line = lines[line_number - 1] if 0 < line_number <= len(lines) else dep
        matched_text = (ast.get_source_segment(content, node) or source_line).strip()[:200]
        added.append(Finding(
            file_path=target.rel_path,
            line_number=line_number,
            category=Category.SCRIPT_INSTALLATION,
            severity=Severity.CRITICAL,
            pattern_id="python-urlretrieve-script-execution",
            matched_text=matched_text,
            extracted_dep=dep[:200],
            description=f"Remote script downloaded with Python urlretrieve and executed: {dep[:200]}",
            scanner_name=ScriptInstallationScanner.name,
        ))
        existing_keys.add(key)
    return added


def _collect_python_urlretrieve_script_helpers(tree: ast.AST) -> dict[str, tuple[str, int]]:
    helpers: dict[str, tuple[str, int]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        params = {
            arg.arg.lower(): (arg.arg, index)
            for index, arg in enumerate(node.args.args)
        }
        if not params:
            continue
        downloaded_vars: dict[str, str] = {}
        for child in ast.walk(node):
            if not isinstance(child, ast.Assign) or not isinstance(child.value, ast.Call):
                continue
            if not _python_call_is_urlretrieve(child.value) or len(child.value.args) < 2:
                continue
            source = child.value.args[0]
            dest = child.value.args[1]
            if not isinstance(source, ast.Name) or source.id.lower() not in params:
                continue
            if not _python_expr_has_script_path_hint(dest):
                continue
            target_name = _python_first_assignment_target_name(child)
            if target_name:
                downloaded_vars[target_name.lower()] = source.id.lower()
        if not downloaded_vars:
            continue
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            executed_vars = [
                var for var in downloaded_vars
                if _python_call_executes_local_script_var(child, var)
            ]
            if not executed_vars:
                continue
            source_key = downloaded_vars[executed_vars[0]]
            helpers[node.name] = params[source_key]
            break
    return helpers


def _python_first_assignment_target_name(node: ast.Assign) -> str:
    for target in node.targets:
        if isinstance(target, ast.Name):
            return target.id
        if isinstance(target, (ast.Tuple, ast.List)) and target.elts:
            first = target.elts[0]
            if isinstance(first, ast.Name):
                return first.id
    return ""


def _python_call_is_urlretrieve(call: ast.Call) -> bool:
    return _python_call_function_name(call.func) == "urlretrieve"


def _python_call_executes_local_script_var(call: ast.Call, var_name: str) -> bool:
    if not isinstance(call.func, ast.Attribute):
        return False
    if not isinstance(call.func.value, ast.Name) or call.func.value.id != "subprocess":
        return False
    if call.func.attr not in {"run", "call", "check_call", "check_output", "Popen"}:
        return False
    if not call.args:
        return False
    return _python_exec_arg_contains_script_var(call.args[0], var_name)


def _python_exec_arg_contains_script_var(node: ast.AST, var_name: str) -> bool:
    if isinstance(node, ast.Name):
        return node.id.lower() == var_name.lower()
    if isinstance(node, (ast.List, ast.Tuple)):
        return any(_python_exec_arg_contains_script_var(item, var_name) for item in node.elts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return (
            _python_exec_arg_contains_script_var(node.left, var_name)
            or _python_exec_arg_contains_script_var(node.right, var_name)
        )
    return False


def _python_expr_has_script_path_hint(node: ast.AST) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            if _PYTHON_SCRIPT_PATH_HINT_RE.search(child.value):
                return True
    try:
        return bool(_PYTHON_SCRIPT_PATH_HINT_RE.search(ast.unparse(node)))
    except Exception:
        return False


def _collect_python_literal_string_assignments(tree: ast.AST) -> dict[str, str]:
    values: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        value = _python_stringish_expr(node.value, values)
        if not value:
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                values[target.id.lower()] = value
    return values


def _python_stringish_expr(node: ast.AST, string_values: dict[str, str]) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return string_values.get(node.id.lower(), "")
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                parts.append("${" + _python_expr_label(value.value) + "}")
            else:
                return ""
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _python_stringish_expr(node.left, string_values)
        right = _python_stringish_expr(node.right, string_values)
        return left + right if left and right else ""
    return ""


def _python_call_arg(call: ast.Call, keyword: str, position: int) -> ast.AST | None:
    for kw in call.keywords:
        if kw.arg == keyword:
            return kw.value
    if position < len(call.args):
        return call.args[position]
    return None


def _python_call_function_name(func: ast.AST) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _python_expr_label(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    try:
        return ast.unparse(node)
    except Exception:
        return "expr"


def _is_metadata_interpreter_pipe(line: str, url: str) -> bool:
    if _PYTHON_JSON_PIPE_RE.search(line):
        return True
    return bool(_METADATA_URL_RE.match(url) and re.search(
        r"\|\s*python3?(?:\.\d+)?\b",
        line,
        re.IGNORECASE,
    ))


def _is_non_control_markdown_script_install_example(
    target: FileTarget,
    finding: Finding,
    lines: list[str],
) -> bool:
    if target.file_type != "agent_instruction" or target.path.suffix.lower() not in _MARKDOWN_DOC_EXTENSIONS:
        return False
    name = target.path.name.lower()
    if name in {doc.lower() for doc in _AGENT_CONTROL_DOC_NAMES}:
        return False
    if any(part.lower() in _AGENT_CONTROL_DOC_DIRS for part in target.path.parts):
        return False
    if _is_reference_markdown_path(target.rel_path):
        return (
            _is_markdown_code_example_line(lines, finding.line_number, finding.extracted_dep)
            or _is_markdown_script_command_line(lines, finding.line_number, finding.extracted_dep)
        )
    if _is_article_markdown_path(target.rel_path):
        return (
            _is_markdown_code_example_line(lines, finding.line_number, finding.extracted_dep)
            or _is_markdown_script_command_line(lines, finding.line_number, finding.extracted_dep)
        )
    if _is_documentation_markdown_path(target.rel_path):
        return (
            _is_markdown_code_example_line(lines, finding.line_number, finding.extracted_dep)
            or _is_markdown_script_command_line(lines, finding.line_number, finding.extracted_dep)
        )
    if not _is_ordinary_markdown_doc_name(name):
        return False
    return _is_markdown_code_example_line(lines, finding.line_number, finding.extracted_dep)


def _is_non_executable_package_config_script_install(
    target: FileTarget,
    finding: Finding,
    lines: list[str],
) -> bool:
    if target.file_type != "package_config":
        return False
    if target.path.name != "package.json":
        return True
    return finding.line_number not in _package_json_script_lines(lines)


def _is_powershell_block_comment_line(target: FileTarget, lines: list[str], line_number: int) -> bool:
    if target.file_type != "script" or target.path.suffix.lower() not in {".ps1", ".psm1", ".psd1"}:
        return False
    in_block = False
    for index, line in enumerate(lines, start=1):
        stripped = line.lstrip()
        if in_block:
            if index == line_number:
                return True
            if "#>" in line:
                in_block = False
            continue
        if stripped.startswith("<#"):
            if index == line_number:
                return True
            if "#>" not in stripped[stripped.find("<#") + 2:]:
                in_block = True
    return False


def _package_json_script_lines(lines: list[str]) -> set[int]:
    script_lines: set[int] = set()
    in_scripts = False
    depth = 0
    for line_number, line in enumerate(lines, start=1):
        if not in_scripts:
            match = re.search(r'"scripts"\s*:\s*\{', line)
            if not match:
                continue
            in_scripts = True
            depth = _json_brace_delta(line[match.start():])
            if re.search(r'"[^"]+"\s*:\s*"', line[match.end():]):
                script_lines.add(line_number)
            if depth <= 0:
                in_scripts = False
            continue

        if re.search(r'^\s*"[^"]+"\s*:\s*"', line):
            script_lines.add(line_number)
        depth += _json_brace_delta(line)
        if depth <= 0:
            in_scripts = False
    return script_lines


def _json_brace_delta(line: str) -> int:
    quote = False
    escaped = False
    delta = 0
    for ch in line:
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            escaped = quote
            continue
        if ch == '"':
            quote = not quote
            continue
        if quote:
            continue
        if ch == "{":
            delta += 1
        elif ch == "}":
            delta -= 1
    return delta


def _is_reference_markdown_path(rel_path: str) -> bool:
    path = "/" + rel_path.replace("\\", "/").lower()
    return "/reference/" in path or "/references/" in path


def _is_article_markdown_path(rel_path: str) -> bool:
    path = "/" + rel_path.replace("\\", "/").lower()
    return "/blogs/" in path or "/blog/" in path or "/_posts/" in path or "/posts/" in path


def _is_documentation_markdown_path(rel_path: str) -> bool:
    path = "/" + rel_path.replace("\\", "/").lower()
    return (
        "/docs/" in path
        or "/doc/" in path
        or "/documentation/" in path
        or "/content/docs/" in path
    )


def _is_ordinary_markdown_doc_name(name: str) -> bool:
    lower = name.lower()
    if lower in {doc.lower() for doc in _ORDINARY_MARKDOWN_DOC_NAMES}:
        return True
    if not lower.endswith((".md", ".mdx")):
        return False
    stem = re.sub(r"\.mdx?$", "", lower)
    normalized = stem.replace("-", "_")
    return (
        normalized == "setup"
        or normalized == "dev_setup"
        or normalized.startswith("readme_")
        or normalized.endswith("_readme")
        or normalized.endswith("_install")
        or normalized.endswith("_installation")
    )


def _is_markdown_script_command_line(lines: list[str], line_number: int, dep: str) -> bool:
    if not (0 < line_number <= len(lines)) or not dep:
        return False
    line = lines[line_number - 1]
    return dep.lower() in line.lower() and bool(_SCRIPT_MARKDOWN_COMMAND_RE.search(line))


def _is_reserved_example_url_in_agent_instruction(target: FileTarget, finding: Finding) -> bool:
    return (
        target.file_type == "agent_instruction"
        and bool(_RESERVED_EXAMPLE_URL_RE.match(finding.extracted_dep))
    )


def _is_markdown_code_example_line(lines: list[str], line_number: int, dep: str) -> bool:
    if not (0 < line_number <= len(lines)):
        return False
    line = lines[line_number - 1]
    if line.startswith(("    ", "\t")):
        return True
    if _is_markdown_inline_code_example(line, dep):
        return True

    in_fence = False
    for index, current in enumerate(lines, start=1):
        stripped = current.lstrip()
        is_fence = stripped.startswith("```") or stripped.startswith("~~~")
        if index == line_number:
            return in_fence or is_fence
        if is_fence:
            in_fence = not in_fence
    return False


def _is_markdown_inline_code_example(line: str, dep: str) -> bool:
    if "`" not in line:
        return False
    dep = dep.lower()
    start = 0
    while True:
        start = line.find("`", start)
        if start == -1:
            return False
        end = line.find("`", start + 1)
        if end == -1:
            return False
        span = line[start + 1:end].lower()
        if (dep and dep in span and _SCRIPT_MARKDOWN_COMMAND_RE.search(span)) or _remote_script_command_in_span(span):
            return True
        start = end + 1


def _remote_script_command_in_span(span: str) -> bool:
    return bool(
        re.search(r"\b(?:curl|wget)\b[^\n|`]*https?://[^\s|`]+[^\n`]*\|\s*(?:bash|sh|zsh|dash|node|python3?)\b", span, re.IGNORECASE)
        or re.search(r"\b(?:irm|iwr|Invoke-RestMethod|Invoke-WebRequest)\b[^\n|`]*https?://[^\s|`]+[^\n`]*\|\s*(?:iex|Invoke-Expression)\b", span, re.IGNORECASE)
        or re.search(r"\b(?:bash|sh|zsh|dash)\s+-c\s+['\"]?\$\(\s*(?:curl|wget)\b", span, re.IGNORECASE)
    )


def _scan_base64_decoded_shell_execution(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type not in set(_FT):
        return []

    existing_keys = {
        (finding.line_number, finding.pattern_id, finding.extracted_dep)
        for finding in existing
    }
    added: list[Finding] = []
    decoded_targets: dict[str, tuple[int, str, str]] = {}
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        decoded_url = _decoded_remote_shell_url(line)
        if _BASE64_DECODE_RE.search(line):
            if _line_executes_base64_decode(line):
                dep = decoded_url or _base64_decode_source(line)
                _append_base64_finding(target, added, existing_keys, line_number, dep, stripped)
            target_token = _base64_decode_output_target(line)
            if target_token:
                decoded_targets[_normalize_shell_token(target_token)] = (
                    line_number,
                    decoded_url or _base64_decode_source(line),
                    stripped,
                )

        if _PYTHON_BASE64_EXEC_RE.search(line):
            dep = decoded_url or _base64_decode_source(line)
            _append_base64_finding(target, added, existing_keys, line_number, dep, stripped)

        for token, (_, dep, _) in list(decoded_targets.items()):
            if _line_executes_shell_target(line, token):
                _append_base64_finding(target, added, existing_keys, line_number, dep, stripped)
                decoded_targets.pop(token, None)
    return added


def _line_executes_base64_decode(line: str) -> bool:
    decode = _BASE64_DECODE_RE.search(line)
    if not decode:
        return False
    tail = line[decode.end():]
    if re.search(r"\|\s*" + _SHELL_PIPE_TARGET, tail, re.IGNORECASE):
        return True
    target = _base64_decode_output_target(line)
    if target and _line_executes_shell_target(tail, _normalize_shell_token(target)):
        return True
    return False


def _base64_decode_output_target(line: str) -> str:
    match = re.search(r"\bbase64\s+(?:--decode|-d)\b[^\n;|&]*>\s*(?P<target>\\?['\"]?\\?\$?[A-Za-z_./-][\w./$-]*\\?['\"]?)", line, re.IGNORECASE)
    return match.group("target") if match else ""


def _line_executes_shell_target(line: str, target: str) -> bool:
    if not target:
        return False
    normalized = _normalize_shell_token(line)
    if target not in normalized:
        return False
    return bool(
        _SHELL_EXEC_RE.search(normalized)
        or _SHELL_SOURCE_EXEC_RE.search(normalized)
        or _line_executes_interpreter_script_target(normalized, target)
        or _line_directly_executes_shell_script_target(normalized, target)
    )


def _normalize_shell_token(value: str) -> str:
    return value.replace("\\", "").strip("'\"")


def _line_directly_executes_shell_script_target(line: str, target: str) -> bool:
    if not _is_direct_shell_script_target(target):
        return False
    variants = [target]
    if not target.startswith(("/", "./", "../", "$")):
        variants.append("./" + target)
    token_pattern = "|".join(
        re.escape(variant)
        for variant in dict.fromkeys(variants)
    )
    return bool(re.search(
        _SHELL_COMMAND_PREFIX
        + _SHELL_EXEC_ENV_PREFIX
        + r"['\"]?(?:"
        + token_pattern
        + r")['\"]?(?:\s|$)",
        line,
        re.IGNORECASE,
    ))


def _line_executes_interpreter_script_target(line: str, target: str) -> bool:
    if _is_shell_variable_target(target):
        return bool(
            re.search(r"(?:script|install|setup|bootstrap)", target, re.IGNORECASE)
            and re.search(
                _SHELL_COMMAND_PREFIX
                + _SHELL_EXEC_ENV_PREFIX
                + _INTERPRETER_PIPE_TARGET
                + r"\b[^\n;|&]*['\"]?"
                + re.escape(target)
                + r"['\"]?(?:\s|$)",
                line,
                re.IGNORECASE,
            )
        )
    if not _PYTHON_SCRIPT_PATH_HINT_RE.search(target):
        return False
    variants = [target]
    if not target.startswith(("/", "./", "../", "$")):
        variants.append("./" + target)
    token_pattern = "|".join(
        re.escape(variant)
        for variant in dict.fromkeys(variants)
    )
    return bool(re.search(
        _SHELL_COMMAND_PREFIX
        + _SHELL_EXEC_ENV_PREFIX
        + _INTERPRETER_PIPE_TARGET
        + r"\b[^\n;|&]*['\"]?(?:"
        + token_pattern
        + r")['\"]?(?:\s|$)",
        line,
        re.IGNORECASE,
    ))


def _is_direct_shell_script_target(target: str) -> bool:
    if _is_shell_variable_target(target):
        return bool(re.search(r"(?:script|install|setup|bootstrap)", target, re.IGNORECASE))
    return bool(re.search(r"\.(?:sh|bash|zsh|dash)$", target, re.IGNORECASE))


def _base64_decode_source(line: str) -> str:
    decoded_url = _decoded_remote_shell_url(line)
    if decoded_url:
        return decoded_url
    literal = _BASE64_LITERAL_RE.search(line)
    if literal:
        return "base64:" + literal.group("value")[:32]
    var = re.search(r"\$[A-Za-z_][A-Za-z0-9_]*", line)
    return var.group(0) if var else "base64-decoded command"


def _decoded_remote_shell_url(line: str) -> str:
    for match in _BASE64_LITERAL_RE.finditer(line):
        try:
            decoded = base64.b64decode(match.group("value"), validate=True).decode("utf-8", "replace")
        except (binascii.Error, ValueError):
            continue
        payload = _REMOTE_SHELL_PAYLOAD_RE.search(decoded)
        if payload:
            return payload.group("url")[:200]
    return ""


def _append_base64_finding(
    target: FileTarget,
    added: list[Finding],
    existing_keys: set[tuple[int, str, str]],
    line_number: int,
    dep: str,
    matched_text: str,
) -> None:
    key = (line_number, "base64-decode-shell-execution", dep)
    if key in existing_keys:
        return
    added.append(Finding(
        file_path=target.rel_path,
        line_number=line_number,
        category=Category.SCRIPT_INSTALLATION,
        severity=Severity.CRITICAL,
        pattern_id="base64-decode-shell-execution",
        matched_text=matched_text[:200],
        extracted_dep=dep[:200],
        description=f"Base64-decoded payload is executed by shell: {dep[:200]}",
        scanner_name=ScriptInstallationScanner.name,
    ))
    existing_keys.add(key)


def _scan_shell_downloaded_script_execution(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type not in set(_FT):
        return []

    existing_keys = {
        (finding.line_number, finding.pattern_id, finding.extracted_dep)
        for finding in existing
    }
    existing_script_line_deps = {
        (finding.line_number, finding.extracted_dep)
        for finding in existing
        if finding.category == Category.SCRIPT_INSTALLATION
    }
    url_vars = _collect_shell_url_vars(lines)
    downloaded_targets = _collect_shell_downloaded_script_targets(lines, url_vars)
    added: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or _PRINT_HELP_RE.match(stripped):
            continue

        for target_token, urls in list(downloaded_targets.items()):
            if not _line_executes_shell_target(line, target_token):
                continue
            pattern_id = (
                "shell-download-then-execute-variable"
                if _is_shell_variable_target(target_token)
                else "shell-download-then-execute-literal"
            )
            for url in sorted(urls):
                key = (line_number, pattern_id, url)
                if key in existing_keys or (line_number, url) in existing_script_line_deps:
                    continue
                added.append(Finding(
                    file_path=target.rel_path,
                    line_number=line_number,
                    category=Category.SCRIPT_INSTALLATION,
                    severity=Severity.CRITICAL,
                    pattern_id=pattern_id,
                    matched_text=stripped[:200],
                    extracted_dep=url[:200],
                    description=f"Remote shell script downloaded to local target and executed: {url[:200]}",
                    scanner_name=ScriptInstallationScanner.name,
                ))
                existing_keys.add(key)
    return added


def _scan_batch_downloaded_script_execution(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type != "script" or not target.rel_path.replace("\\", "/").lower().endswith((".cmd", ".bat")):
        return []

    url_vars = _collect_batch_url_vars(lines)
    downloaded_targets = _collect_batch_downloaded_script_targets(lines, url_vars)
    if not downloaded_targets:
        return []

    existing_keys = {
        (finding.line_number, finding.pattern_id, finding.extracted_dep)
        for finding in existing
    }
    added: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.lower().startswith(("rem ", "::")):
            continue
        for target_name, urls in downloaded_targets.items():
            if not _batch_line_executes_script_target(line, target_name):
                continue
            for url in sorted(urls):
                key = (line_number, "batch-download-then-execute-script", url)
                if key in existing_keys:
                    continue
                added.append(Finding(
                    file_path=target.rel_path,
                    line_number=line_number,
                    category=Category.SCRIPT_INSTALLATION,
                    severity=Severity.CRITICAL,
                    pattern_id="batch-download-then-execute-script",
                    matched_text=stripped[:200],
                    extracted_dep=url[:200],
                    description=f"Remote script downloaded in batch file and executed: {url[:200]}",
                    scanner_name=ScriptInstallationScanner.name,
                ))
                existing_keys.add(key)
    return added


def _collect_batch_url_vars(lines: list[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.lower().startswith(("rem ", "::")):
            continue
        match = re.match(
            r"set\s+(?P<var>[A-Za-z_][A-Za-z0-9_]*)=(?P<url>\"?https?://[^\"\s]+\"?)",
            stripped,
            re.IGNORECASE,
        )
        if match:
            values[match.group("var").lower()] = match.group("url").strip("\"")
    return values


def _collect_batch_downloaded_script_targets(
    lines: list[str],
    url_vars: dict[str, str],
) -> dict[str, set[str]]:
    downloaded: dict[str, set[str]] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.lower().startswith(("rem ", "::")):
            continue
        if not re.search(r"\bcurl\b", stripped, re.IGNORECASE):
            continue
        output = re.search(
            r"(?:--output|-o)\s+(?P<target>\"?[^\"\s]+\"?)",
            stripped,
            re.IGNORECASE,
        )
        if not output:
            continue
        target_name = output.group("target").strip("\"")
        if not _PYTHON_SCRIPT_PATH_HINT_RE.search(target_name):
            continue
        urls = _extract_batch_download_urls(stripped, url_vars)
        if urls:
            downloaded.setdefault(target_name.lower(), set()).update(urls)
    return downloaded


def _extract_batch_download_urls(line: str, url_vars: dict[str, str]) -> list[str]:
    urls = [
        match.group(0).strip("\"")
        for match in re.finditer(r"https?://[^\"\s]+", line, re.IGNORECASE)
    ]
    for match in re.finditer(r"%(?P<var>[A-Za-z_][A-Za-z0-9_]*)%", line):
        url = url_vars.get(match.group("var").lower())
        if url:
            urls.append(url)
    return _unique_preserve_order(urls)


def _batch_line_executes_script_target(line: str, target_name: str) -> bool:
    normalized = line.strip().strip("\"").lower()
    if not normalized or normalized.startswith(("rem ", "::")):
        return False
    target = re.escape(target_name.lower())
    interpreter = (
        r"(?:"
        r"(?:\.\\|[A-Za-z]:\\|%[A-Za-z_][A-Za-z0-9_]*%\\|[^\s\"&|<>]+\\)?"
        r"(?:python(?:\.exe)?|py(?:\.exe)?|node(?:\.exe)?|powershell(?:\.exe)?|pwsh(?:\.exe)?)"
        r")"
    )
    return bool(re.search(
        r"(?:^|[&|]\s*)"
        + interpreter
        + r"\s+\"?(?:\.\\)?"
        + target
        + r"\"?(?:\s|$)",
        normalized,
        re.IGNORECASE,
    ))


def _collect_shell_downloaded_script_targets(
    lines: list[str],
    url_vars: dict[str, str],
) -> dict[str, set[str]]:
    downloaded_targets: dict[str, set[str]] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or _PRINT_HELP_RE.match(stripped):
            continue
        urls = [
            *_extract_shell_download_urls(line),
            *_extract_shell_download_var_urls(line, url_vars),
            *_extract_shell_download_composed_script_urls(line),
        ]
        if not urls:
            continue
        for output_target in _shell_download_output_targets(line):
            normalized = _normalize_shell_token(output_target)
            if _is_shell_download_script_target(normalized):
                downloaded_targets.setdefault(normalized, set()).update(urls)
        for output_target in _shell_download_default_output_targets(line, urls):
            downloaded_targets.setdefault(output_target, set()).update(urls)
    _add_shell_downloaded_script_target_aliases(lines, downloaded_targets)
    return downloaded_targets


def _add_shell_downloaded_script_target_aliases(
    lines: list[str],
    downloaded_targets: dict[str, set[str]],
) -> None:
    if not downloaded_targets:
        return
    literal_targets = [
        target for target in downloaded_targets
        if not _is_shell_variable_target(target)
    ]
    if not literal_targets:
        return
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or _PRINT_HELP_RE.match(stripped):
            continue
        match = re.search(
            r"(?:^|\s)(?:local\s+)?(?P<var>[A-Za-z_][A-Za-z0-9_]*)="
            r"(?P<value>['\"]?[^'\"\s;|&]+['\"]?)",
            line,
        )
        if not match:
            continue
        value = _normalize_shell_token(match.group("value"))
        for target in literal_targets:
            if target not in value:
                continue
            downloaded_targets.setdefault("$" + match.group("var"), set()).update(downloaded_targets[target])


def _collect_shell_url_vars(lines: list[str]) -> dict[str, str]:
    url_vars: dict[str, str] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or _PRINT_HELP_RE.match(stripped):
            continue
        for match in _SHELL_URL_ASSIGN_RE.finditer(line):
            url_vars[match.group("var")] = match.group("url")
        for match in _SHELL_ASSIGN_RE.finditer(line):
            value = _normalize_shell_token(match.group("value"))
            url = _resolve_shell_url_assignment(value, url_vars)
            if url:
                url_vars[match.group("var")] = url
    return url_vars


def _resolve_shell_url_assignment(value: str, url_vars: dict[str, str]) -> str:
    if re.match(r"^https?://", value, re.IGNORECASE):
        return value

    literal = re.search(r"https?://[^'\"\s]+", value, re.IGNORECASE)
    if literal:
        return _trim_unmatched_trailing_shell_braces(literal.group(0))

    for name, url in url_vars.items():
        prefixes = (f"${name}", "${" + name + "}")
        for prefix in prefixes:
            if not value.startswith(prefix):
                continue
            suffix = value[len(prefix):]
            if not suffix or re.search(r"\s", suffix):
                continue
            return url + suffix
    return ""


def _trim_unmatched_trailing_shell_braces(value: str) -> str:
    while value.endswith("}") and value.count("}") > value.count("${"):
        value = value[:-1]
    return value


def _extract_shell_download_var_urls(line: str, url_vars: dict[str, str]) -> list[str]:
    if not url_vars or not re.search(r"\b(?:curl|wget)\b", line, re.IGNORECASE):
        return []
    urls: list[str] = []
    for match in re.finditer(r"\$(?:\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)\}|(?P<plain>[A-Za-z_][A-Za-z0-9_]*))", line):
        url = url_vars.get(match.group("braced") or match.group("plain") or "")
        if url:
            urls.append(url)
    return _unique_preserve_order(urls)


def _extract_shell_download_urls(line: str) -> list[str]:
    if not re.search(r"\b(?:curl|wget)\b", line, re.IGNORECASE):
        return []
    return [
        match.group(0).rstrip("\\")
        for match in re.finditer(_PIPELINE_URL_TOKEN, line, re.IGNORECASE)
    ]


def _shell_download_default_output_targets(line: str, urls: list[str]) -> list[str]:
    if not urls or not re.search(r"\bwget\b", line, re.IGNORECASE):
        return []
    if _shell_download_output_targets(line):
        return []
    if re.search(r"(?:^|\s)(?:-P|--directory-prefix)(?:=|\s+)", line):
        return []
    targets: list[str] = []
    for url in urls:
        if not url.startswith(("http://", "https://")):
            continue
        path = url.split("?", 1)[0].split("#", 1)[0].rstrip("/")
        basename = path.rsplit("/", 1)[-1]
        if basename and _is_shell_download_script_target(basename):
            targets.append(basename)
    return _unique_preserve_order(targets)


def _extract_shell_download_composed_script_urls(line: str) -> list[str]:
    if "$" not in line or not re.search(r"\b(?:curl|wget)\b", line, re.IGNORECASE):
        return []
    try:
        tokens = shlex.split(line)
    except ValueError:
        return []
    urls: list[str] = []
    skip_next = False
    for token in tokens[1:]:
        if skip_next:
            skip_next = False
            continue
        if token in {">", "1>", "2>"}:
            skip_next = True
            continue
        if token in {"-o", "-O", "--output", "--output-document"}:
            skip_next = True
            continue
        if token.startswith(("--output=", "--output-document=")):
            continue
        if token.startswith("-"):
            continue
        dep = _normalize_shell_token(token)
        if not dep.startswith("$") or not _PYTHON_SCRIPT_PATH_HINT_RE.search(dep):
            continue
        urls.append(dep)
    return _unique_preserve_order(urls)


def _shell_download_output_targets(line: str) -> list[str]:
    targets: list[str] = []
    for regex in (_SHELL_DOWNLOAD_REDIRECT_RE, _CURL_DOWNLOAD_OUTPUT_RE):
        for match in regex.finditer(line):
            targets.append(match.group("out"))
    if re.search(r"\bwget\b", line, re.IGNORECASE):
        for match in _WGET_DOWNLOAD_OUTPUT_RE.finditer(line):
            targets.append(match.group("out"))
    return _unique_preserve_order(targets)


def _is_shell_download_script_target(target: str) -> bool:
    if not target or target in {"-", "/dev/null"}:
        return False
    if target.startswith("-") or target.startswith(("http://", "https://")):
        return False
    if target.endswith("/"):
        return False
    if _is_shell_variable_target(target):
        return True
    return bool(_PYTHON_SCRIPT_PATH_HINT_RE.search(target))


def _is_shell_variable_target(target: str) -> bool:
    return target.startswith("$")


def _unique_preserve_order(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _scan_powershell_iex_variable_urls(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type not in set(_FT):
        return []

    url_vars: dict[str, str] = {}
    for line in lines:
        for match in _POWERSHELL_URL_ASSIGN_RE.finditer(line):
            url_vars[match.group("var").lower()] = match.group("url")

    if not url_vars:
        return []

    existing_keys = {
        (finding.line_number, finding.pattern_id, finding.extracted_dep)
        for finding in existing
    }
    added: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or _PRINT_HELP_RE.match(stripped):
            continue
        for match in _POWERSHELL_IEX_WEB_VAR_RE.finditer(line):
            var = match.group("var").lower()
            url = url_vars.get(var)
            if not url:
                continue
            key = (line_number, "powershell-iex-web-variable", url)
            if key in existing_keys:
                continue
            added.append(Finding(
                file_path=target.rel_path,
                line_number=line_number,
                category=Category.SCRIPT_INSTALLATION,
                severity=Severity.CRITICAL,
                pattern_id="powershell-iex-web-variable",
                matched_text=stripped[:200],
                extracted_dep=url[:200],
                description=f"Remote PowerShell script executed via Invoke-Expression variable URL: {url[:200]}",
                scanner_name=ScriptInstallationScanner.name,
            ))
            existing_keys.add(key)
    return added


def _scan_powershell_downloaded_script_variables(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type not in set(_FT):
        return []

    url_vars = _collect_powershell_url_vars(lines)
    downloaded_script_vars: dict[str, set[str]] = {}
    downloaded_script_paths: dict[str, set[str]] = {}
    downloaded_script_var_aliases: dict[str, set[str]] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or _PRINT_HELP_RE.match(stripped):
            continue
        match = _POWERSHELL_WEB_DOWNLOAD_VAR_RE.search(line)
        if match:
            source_vars = _powershell_vars(match.group("body"))
            urls = {
                url
                for var in source_vars
                for url in url_vars.get(var.lower(), set())
            }
            urls.update(_extract_powershell_literal_urls(match.group("body")))
            if urls:
                downloaded_script_vars.setdefault(match.group("out").lower(), set()).update(urls)

        match = _POWERSHELL_WEB_DOWNLOAD_LITERAL_RE.search(line)
        if match:
            urls = set(_extract_powershell_literal_urls(match.group("body")))
            source_vars = _powershell_vars(match.group("body"))
            urls.update(
                url
                for var in source_vars
                for url in url_vars.get(var.lower(), set())
            )
            out_path = _normalize_powershell_script_path(match.group("out"))
            if urls and out_path:
                downloaded_script_paths.setdefault(out_path, set()).update(urls)

        match = _POWERSHELL_WEB_DOWNLOAD_ANY_OUT_RE.search(line)
        if match:
            urls = _extract_powershell_download_source_urls(match.group("body"), url_vars)
            _record_powershell_download_target(
                downloaded_script_vars,
                downloaded_script_paths,
                match.group("out"),
                urls,
            )

        match = _POWERSHELL_WEBCLIENT_DOWNLOADFILE_RE.search(line)
        if match:
            urls = _extract_powershell_download_source_urls(match.group("src"), url_vars)
            _record_powershell_download_target(
                downloaded_script_vars,
                downloaded_script_paths,
                match.group("out"),
                urls,
            )

        match = _POWERSHELL_VAR_ALIAS_RE.search(line)
        if match:
            src = match.group("src").lower()
            roots: set[str] = set()
            if src in downloaded_script_vars:
                roots.add(src)
            roots.update(downloaded_script_var_aliases.get(src, set()))
            if roots:
                downloaded_script_var_aliases.setdefault(match.group("dst").lower(), set()).update(roots)

    if not downloaded_script_vars and not downloaded_script_paths and not downloaded_script_var_aliases:
        return []

    existing_keys = {
        (finding.line_number, finding.pattern_id, finding.extracted_dep)
        for finding in existing
    }
    added: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or _PRINT_HELP_RE.match(stripped):
            continue
        if _POWERSHELL_INVOKE_EXPRESSION_RE.search(line):
            invoked_roots: set[str] = set()
            for var in _powershell_vars(line):
                var_key = var.lower()
                if var_key in downloaded_script_vars:
                    invoked_roots.add(var_key)
                invoked_roots.update(downloaded_script_var_aliases.get(var_key, set()))
            for root_var in sorted(invoked_roots):
                for url in sorted(downloaded_script_vars.get(root_var, set())):
                    key = (line_number, "powershell-download-then-execute-variable", url)
                    if key in existing_keys:
                        continue
                    added.append(Finding(
                        file_path=target.rel_path,
                        line_number=line_number,
                        category=Category.SCRIPT_INSTALLATION,
                        severity=Severity.CRITICAL,
                        pattern_id="powershell-download-then-execute-variable",
                        matched_text=stripped[:200],
                        extracted_dep=url[:200],
                        description=f"Remote PowerShell script downloaded to variable path and executed: {url[:200]}",
                        scanner_name=ScriptInstallationScanner.name,
                    ))
                    existing_keys.add(key)

        match = _POWERSHELL_SCRIPT_VAR_EXEC_RE.search(line)
        literal_match = _POWERSHELL_SCRIPT_LITERAL_EXEC_RE.search(line)
        if literal_match:
            script_path = _normalize_powershell_script_path(
                literal_match.group("call_path")
                or literal_match.group("direct_path")
                or literal_match.group("file_path")
                or ""
            )
            for url in sorted(downloaded_script_paths.get(script_path, set())):
                key = (line_number, "powershell-download-then-execute-literal", url)
                if key in existing_keys:
                    continue
                added.append(Finding(
                    file_path=target.rel_path,
                    line_number=line_number,
                    category=Category.SCRIPT_INSTALLATION,
                    severity=Severity.CRITICAL,
                    pattern_id="powershell-download-then-execute-literal",
                    matched_text=stripped[:200],
                    extracted_dep=url[:200],
                    description=f"Remote PowerShell script downloaded to local path and executed: {url[:200]}",
                    scanner_name=ScriptInstallationScanner.name,
                ))
                existing_keys.add(key)
        if not match:
            continue

        script_var = (
            match.group("call_var")
            or match.group("file_var")
            or match.group("wsl_var")
            or match.group("shell_var")
            or ""
        ).lower()
        for url in sorted(downloaded_script_vars.get(script_var, set())):
            key = (line_number, "powershell-download-then-execute-variable", url)
            if key in existing_keys:
                continue
            added.append(Finding(
                file_path=target.rel_path,
                line_number=line_number,
                category=Category.SCRIPT_INSTALLATION,
                severity=Severity.CRITICAL,
                pattern_id="powershell-download-then-execute-variable",
                matched_text=stripped[:200],
                extracted_dep=url[:200],
                description=f"Remote PowerShell script downloaded to variable path and executed: {url[:200]}",
                scanner_name=ScriptInstallationScanner.name,
            ))
            existing_keys.add(key)
    return added


def _scan_powershell_downloaded_scriptblock_execution(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type not in set(_FT):
        return []
    if not any("[ScriptBlock]::Create" in line for line in lines):
        return []

    array_values = _collect_powershell_string_arrays(lines)
    foreach_values = _collect_powershell_foreach_values(lines, array_values)
    url_vars = _collect_powershell_url_vars(lines)
    url_vars.update(_collect_powershell_expanded_url_vars(lines, url_vars, foreach_values))
    path_var_files = _collect_powershell_path_var_script_names(lines, foreach_values)
    downloaded_urls = _collect_powershell_downloaded_script_urls_by_name(lines, url_vars, path_var_files)
    if not downloaded_urls:
        return []

    content_var_files: dict[str, set[str]] = {}
    scriptblock_var_files: dict[str, set[str]] = {}
    existing_keys = {
        (finding.line_number, finding.pattern_id, finding.extracted_dep)
        for finding in existing
    }
    added: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or _PRINT_HELP_RE.match(stripped):
            continue

        content_match = re.search(
            r"(?P<content>\$[A-Za-z_][A-Za-z0-9_]*)\s*=\s*Get-Content\b"
            r"[^\n]*?(?P<src>\$[A-Za-z_][A-Za-z0-9_]*)\b",
            line,
            re.IGNORECASE,
        )
        if content_match:
            src = content_match.group("src").lower()
            files = path_var_files.get(src, set())
            if files:
                content_var_files.setdefault(content_match.group("content").lower(), set()).update(files)

        block_match = re.search(
            r"(?P<block>\$[A-Za-z_][A-Za-z0-9_]*)\s*=\s*\[ScriptBlock\]::Create\s*\(\s*"
            r"(?P<content>\$[A-Za-z_][A-Za-z0-9_]*)\s*\)",
            line,
            re.IGNORECASE,
        )
        if block_match:
            content_var = block_match.group("content").lower()
            files = content_var_files.get(content_var, set())
            if files:
                scriptblock_var_files.setdefault(block_match.group("block").lower(), set()).update(files)

        exec_match = re.search(
            r"^\s*&\s*(?P<block>\$[A-Za-z_][A-Za-z0-9_]*)\b",
            line,
            re.IGNORECASE,
        )
        if not exec_match:
            continue
        for script_name in sorted(scriptblock_var_files.get(exec_match.group("block").lower(), set())):
            for url in sorted(downloaded_urls.get(script_name, set())):
                key = (line_number, "powershell-download-scriptblock-execution", url)
                if key in existing_keys:
                    continue
                added.append(Finding(
                    file_path=target.rel_path,
                    line_number=line_number,
                    category=Category.SCRIPT_INSTALLATION,
                    severity=Severity.CRITICAL,
                    pattern_id="powershell-download-scriptblock-execution",
                    matched_text=stripped[:200],
                    extracted_dep=url[:200],
                    description=f"Remote PowerShell script downloaded, loaded as ScriptBlock, and executed: {url[:200]}",
                    scanner_name=ScriptInstallationScanner.name,
                ))
                existing_keys.add(key)
    return added


def _collect_powershell_string_arrays(lines: list[str]) -> dict[str, set[str]]:
    arrays: dict[str, set[str]] = {}
    current_var = ""
    values: set[str] = set()
    for line in lines:
        if current_var:
            values.update(_powershell_quoted_strings(line))
            if ")" in line:
                arrays[current_var] = set(values)
                current_var = ""
                values = set()
            continue

        match = re.search(
            r"(?P<var>\$[A-Za-z_][A-Za-z0-9_]*)\s*=\s*@\(",
            line,
            re.IGNORECASE,
        )
        if not match:
            continue
        current_var = match.group("var").lower()
        tail = line[match.end():]
        values = set(_powershell_quoted_strings(tail))
        if ")" in tail:
            arrays[current_var] = set(values)
            current_var = ""
            values = set()
    return arrays


def _collect_powershell_foreach_values(
    lines: list[str],
    array_values: dict[str, set[str]],
) -> dict[str, set[str]]:
    values: dict[str, set[str]] = {}
    for line in lines:
        match = re.search(
            r"\bforeach\s*\(\s*(?P<item>\$[A-Za-z_][A-Za-z0-9_]*)\s+in\s+"
            r"(?P<array>\$[A-Za-z_][A-Za-z0-9_]*)\s*\)",
            line,
            re.IGNORECASE,
        )
        if match:
            items = array_values.get(match.group("array").lower(), set())
            if items:
                values.setdefault(match.group("item").lower(), set()).update(items)
    return values


def _collect_powershell_expanded_url_vars(
    lines: list[str],
    url_vars: dict[str, set[str]],
    foreach_values: dict[str, set[str]],
) -> dict[str, set[str]]:
    expanded: dict[str, set[str]] = {}
    known_urls = {key: set(value) for key, value in url_vars.items()}
    for line in lines:
        match = re.search(
            r"(?P<var>\$[A-Za-z_][A-Za-z0-9_]*)\s*=\s*['\"](?P<value>[^'\"]+)['\"]",
            line,
            re.IGNORECASE,
        )
        if not match:
            continue
        urls = _expand_powershell_url_template(match.group("value"), known_urls, foreach_values)
        if not urls:
            continue
        expanded.setdefault(match.group("var").lower(), set()).update(urls)
        known_urls.setdefault(match.group("var").lower(), set()).update(urls)
    return expanded


def _expand_powershell_url_template(
    value: str,
    url_vars: dict[str, set[str]],
    foreach_values: dict[str, set[str]],
) -> set[str]:
    values = {value}
    for var, urls in url_vars.items():
        expanded: set[str] = set()
        for current in values:
            if not re.search(rf"(?<![\w.-]){re.escape(var)}(?![\w.-])", current, re.IGNORECASE):
                expanded.add(current)
                continue
            expanded.update(re.sub(rf"(?<![\w.-]){re.escape(var)}(?![\w.-])", url, current, flags=re.IGNORECASE) for url in urls)
        values = expanded
    for var, replacements in foreach_values.items():
        expanded = set()
        for current in values:
            if not re.search(rf"(?<![\w.-]){re.escape(var)}(?![\w.-])", current, re.IGNORECASE):
                expanded.add(current)
                continue
            expanded.update(
                re.sub(rf"(?<![\w.-]){re.escape(var)}(?![\w.-])", replacement, current, flags=re.IGNORECASE)
                for replacement in replacements
            )
        values = expanded
    return {current for current in values if current.startswith(("http://", "https://"))}


def _collect_powershell_path_var_script_names(
    lines: list[str],
    foreach_values: dict[str, set[str]],
) -> dict[str, set[str]]:
    path_vars: dict[str, set[str]] = {}
    for line in lines:
        match = re.search(
            r"(?P<var>\$[A-Za-z_][A-Za-z0-9_]*)\s*=\s*Join-Path\b[^\n]*?"
            r"(?P<name>['\"][^'\"]+['\"]|\$[A-Za-z_][A-Za-z0-9_]*)\s*(?:#.*)?$",
            line,
            re.IGNORECASE,
        )
        if not match:
            continue
        names: set[str] = set()
        name_expr = match.group("name").strip()
        if name_expr.startswith("$"):
            names.update(foreach_values.get(name_expr.lower(), set()))
        else:
            names.add(name_expr.strip("'\""))
        script_names = {
            name for name in names
            if _PYTHON_SCRIPT_PATH_HINT_RE.search(name)
        }
        if script_names:
            path_vars.setdefault(match.group("var").lower(), set()).update(script_names)
    return path_vars


def _collect_powershell_downloaded_script_urls_by_name(
    lines: list[str],
    url_vars: dict[str, set[str]],
    path_var_files: dict[str, set[str]],
) -> dict[str, set[str]]:
    downloaded: dict[str, set[str]] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or _PRINT_HELP_RE.match(stripped):
            continue
        match = _POWERSHELL_WEB_DOWNLOAD_ANY_OUT_RE.search(line)
        if not match:
            continue
        urls = _extract_powershell_download_source_urls(match.group("body"), url_vars)
        if not urls:
            continue
        out_var = _powershell_single_var(match.group("out")).lower()
        script_names = path_var_files.get(out_var, set()) if out_var else set()
        if not script_names:
            out_path = _normalize_powershell_script_path(match.group("out"))
            if _PYTHON_SCRIPT_PATH_HINT_RE.search(out_path):
                script_names.add(out_path.rsplit("/", 1)[-1])
        for script_name in script_names:
            matching_urls = {
                url for url in urls
                if url.lower().split("?", 1)[0].split("#", 1)[0].endswith(script_name.lower())
            }
            if matching_urls:
                downloaded.setdefault(script_name, set()).update(matching_urls)
    return downloaded


def _powershell_quoted_strings(text: str) -> list[str]:
    return [
        match.group("value")
        for match in re.finditer(r"['\"](?P<value>[^'\"]+)['\"]", text)
    ]


def _collect_powershell_url_vars(lines: list[str]) -> dict[str, set[str]]:
    url_vars: dict[str, set[str]] = {}
    for line in lines:
        for match in _POWERSHELL_URL_ASSIGN_RE.finditer(line):
            url_vars.setdefault(match.group("var").lower(), set()).add(match.group("url"))
    return url_vars


def _extract_powershell_download_source_urls(
    text: str,
    url_vars: dict[str, set[str]],
) -> set[str]:
    urls = set(_extract_powershell_literal_urls(text))
    for var in _powershell_vars(text):
        urls.update(url_vars.get(var.lower(), set()))
    for match in _POWERSHELL_COMPOSED_SCRIPT_URL_RE.finditer(text):
        base_var = match.group("base")
        suffix = match.group("suffix")
        base_urls = url_vars.get(base_var.lower(), set())
        if base_urls:
            urls.update(base_url + suffix for base_url in base_urls)
        else:
            urls.add("${" + base_var.lstrip("$") + "}" + suffix)
    return urls


def _record_powershell_download_target(
    downloaded_script_vars: dict[str, set[str]],
    downloaded_script_paths: dict[str, set[str]],
    out: str,
    urls: set[str],
) -> None:
    if not urls:
        return
    out_var = _powershell_single_var(out)
    if out_var:
        downloaded_script_vars.setdefault(out_var.lower(), set()).update(urls)
        return
    out_path = _normalize_powershell_script_path(out)
    if out_path and _PYTHON_SCRIPT_PATH_HINT_RE.search(out_path):
        downloaded_script_paths.setdefault(out_path, set()).update(urls)


def _powershell_single_var(text: str) -> str:
    text = text.strip().strip("'\"")
    return text if re.fullmatch(r"\$[A-Za-z_][A-Za-z0-9_]*", text) else ""


def _extract_powershell_literal_urls(text: str) -> list[str]:
    return [match.group(0).strip("'\"") for match in _POWERSHELL_LITERAL_URL_RE.finditer(text)]


def _powershell_vars(text: str) -> list[str]:
    return re.findall(r"\$[A-Za-z_][A-Za-z0-9_]*", text)


def _normalize_powershell_script_path(path: str) -> str:
    path = path.strip().strip("'\"")
    path = path.replace("\\", "/")
    path = re.sub(r"^(?:\./)+", "", path)
    return path.lower()


def _dedupe_findings_by_file_dependency(findings: list[Finding]) -> list[Finding]:
    deduped: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for finding in findings:
        key = (finding.file_path, finding.pattern_id, finding.extracted_dep)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped


def _is_printed_powershell_webclient_downloadstring_hint(finding: Finding) -> bool:
    if finding.pattern_id != "powershell-webclient-downloadstring-iex":
        return False
    return bool(_PRINT_HELP_RE.match(finding.matched_text.strip()))
