"""Category 2: Direct binary downloads via curl/wget/gh/powershell/aria2c."""
from __future__ import annotations

import ast
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

_FT = ["ci", "script", "build", "dockerfile", "github_action", "agent_instruction", "devcontainer"]
_ALL_SCRIPTABLE = ["ci", "script", "build", "dockerfile", "github_action", "agent_instruction", "devcontainer"]

_LOCALHOST = r"localhost|127\.0\.0\.1|0\.0\.0\.0|::1"
_JSON_API_URL_RE = re.compile(
    r"https?://(?:"
    r"api\.github\.com/"
    r"|api\.appcenter\.ms/"
    r"|api\.powerbi\.com/"
    r"|marketplace\.visualstudio\.com/_apis/"
    r"|dev\.azure\.com/[^/\s]+/"
    r"|[^/\s]+\.visualstudio\.com/_apis/"
    r")",
    re.IGNORECASE,
)
_BINARY_ACCEPT_RE = re.compile(
    r"\bAccept:\s*(?:application/octet-stream|application/zip|application/x-(?:gzip|tar|msdownload))\b",
    re.IGNORECASE,
)
_JSON_OUTPUT_RE = re.compile(
    r"(?:^|\s)(?:-[A-Za-z]*[oO]\b|--output(?:=|\s))\s+['\"]?[^'\"\s]+\.(?:json|txt)\b",
    re.IGNORECASE,
)
_YAML_METADATA_OUTPUT_RE = re.compile(
    r"(?:^|\s)(?:-[A-Za-z]*[oO]\b|--output(?:=|\s))\s+['\"]?[^'\"\s]+\.(?:ya?ml)\b",
    re.IGNORECASE,
)
_JSON_METADATA_URL_RE = re.compile(
    r"(?:[?&][\w.-]*json(?:[=&?#/]|$)|[?&]format=(?:json|js)(?:[&#]|$)|\.json(?:[?#]|$))",
    re.IGNORECASE,
)
_YAML_METADATA_URL_RE = re.compile(r"\.ya?ml(?:[?#]|$)", re.IGNORECASE)
_CONTAINER_REGISTRY_METADATA_URL_RE = re.compile(
    r"/v2/(?:[^'\"\s)]+/)?(?:tags/list|manifests/[^'\"\s)]+)(?:[?#]|$)",
    re.IGNORECASE,
)
_TEXT_METADATA_URL_RE = re.compile(
    r"(?:/(?:current|latest)[_-]?version\.txt(?:[?#]|$)|\.(?:html?|txt)(?:[?#]|$))",
    re.IGNORECASE,
)
_CHECKSUM_TEXT_URL_RE = re.compile(
    r"(?:(?:sha\d*sums?|checksums?)\.txt|\.(?:sha1|sha256|sha512|md5))(?:[?#]|$)",
    re.IGNORECASE,
)
_METADATA_ASSIGNED_VAR_RE = re.compile(r"(?:json|response|metadata|version|ver)", re.IGNORECASE)
_TEXT_METADATA_PIPE_RE = re.compile(r"\|\s*(?:grep|awk|sed)\b", re.IGNORECASE)
_JSON_PARSE_PIPE_RE = re.compile(
    r"\|\s*(?:jq\b|python3?\s+-c\s+['\"][^'\"]*\bjson\b)",
    re.IGNORECASE,
)
_CURL_ASSIGNED_VAR_RE = re.compile(r"^\s*(?P<var>[A-Za-z_][A-Za-z0-9_]*)=\$\(", re.IGNORECASE)
_TEXT_METADATA_OUTPUT_RE = re.compile(
    r"(?:^|\s)(?:-[A-Za-z]*[oO]\b|--output(?:=|\s))\s+['\"]?(?:COPYING|LICENSE)(?:\.[A-Za-z0-9_-]+)?(?:['\"]|\s|$)",
    re.IGNORECASE,
)
_NULL_OUTPUT_TOKEN = (
    r"(?:-(?=(?-i:[A-Za-z]*o)(?:\s|$))[A-Za-z]+|--output(?:=|\s+))"
    r"\s+['\"]?/dev/null(?:['\"`]|\s|$)"
)
_NULL_OUTPUT_RE = re.compile(r"(?:^|\s)" + _NULL_OUTPUT_TOKEN, re.IGNORECASE)
_WGET_NULL_OUTPUT_RE = re.compile(
    r"\bwget\b[^\n]*?(?:-O\s+|--output-document(?:=|\s+))['\"]?/dev/null(?:['\"`]|\s|$)",
    re.IGNORECASE,
)
_WGET_SPIDER_RE = re.compile(r"\bwget\b[^\n]*?--spider\b", re.IGNORECASE)
_WGET_STDOUT_OUTPUT_RE = re.compile(
    r"\bwget\b[^\n]*?(?:-[A-Za-z]*O-(?:\s|$)|-[A-Za-z]*O\s+-(?:\s|$)|--output-document(?:=|\s+)-(?:\s|$))",
    re.IGNORECASE,
)
_VAR_NAME = r"[A-Za-z_][A-Za-z0-9_]*"
_URLISH_VAR_NAME = (
    r"(?:"
    r"(?i:(?:[A-Za-z_][A-Za-z0-9_]*_)?(?:url|uri)(?:_[A-Za-z0-9_]+)*)"
    r"|(?i:(?!(?:curl|wget)[A-Za-z0-9_]*(?:url|uri)$)[A-Za-z_][A-Za-z0-9_]*(?:url|uri))"
    r"|(?-i:[A-Za-z_][A-Za-z0-9_]*(?:Url|Uri)(?:[A-Z0-9_][A-Za-z0-9_]*)?)"
    r")"
)
_SHELL_URLISH_VAR = (
    r"\$\{?"
    r"(?=" + _URLISH_VAR_NAME + r"\}?(?![A-Za-z0-9_]))"
    + _VAR_NAME + r"\}?"
    r"(?:"
    r"\$\{" + _VAR_NAME + r"\}"
    r"|[./_-][^'\"\s$]*"
    r")*"
)
_BATCH_URLISH_VAR = (
    r"%"
    r"(?=" + _URLISH_VAR_NAME + r"%(?![A-Za-z0-9_]))"
    + _VAR_NAME + r"%"
    r"(?:[./_-][^'\"\s%]*)?"
)
_URLISH_VAR = r"(?:" + _SHELL_URLISH_VAR + r"|" + _BATCH_URLISH_VAR + r")"
_SHELL_SUBSTITUTION_TOKEN = r"\$\([^)]*\)"
_SHELL_PARAMETER_EXPANSION_TOKEN = r"\$\{[A-Za-z_][A-Za-z0-9_]*[^}\n]*\}"
_URL_PART = (
    r"(?:"
    + r"\$\{\{.*?\}\}"
    + r"|"
    + _SHELL_PARAMETER_EXPANSION_TOKEN
    + r"|"
    + _SHELL_SUBSTITUTION_TOKEN
    + r"|(?:(?!\$\{)[^'\"\s)\]])"
    + r")"
)
_CURL_ASSIGNED_URL_PART = (
    r"(?:"
    + r"\$\{\{.*?\}\}"
    + r"|"
    + _SHELL_PARAMETER_EXPANSION_TOKEN
    + r"|"
    + _SHELL_SUBSTITUTION_TOKEN
    + r"|(?:(?!\$\{)[^'\"\s)])"
    + r")"
)
_GITHUB_RELEASE_URL_PART = (
    r"(?:"
    + r"\$\{\{.*?\}\}"
    + r"|"
    + _SHELL_PARAMETER_EXPANSION_TOKEN
    + r"|"
    + _SHELL_SUBSTITUTION_TOKEN
    + r"|(?:(?!\$\{)[^`'\"\s)\]|])"
    + r")"
)
_URL_TOKEN = (
    r"https?://(?!" + _LOCALHOST + r")"
    + _URL_PART + r"+"
)
_CURL_ASSIGNED_URL_TOKEN = (
    r"https?://(?!" + _LOCALHOST + r")"
    + _CURL_ASSIGNED_URL_PART + r"+"
)
_GITHUB_RELEASE_URL_TOKEN = (
    r"https?://github\.com/[^/\s]+/[^/\s]+/releases/download/"
    + _GITHUB_RELEASE_URL_PART + r"+"
)
_CURRENT_IP_LOOKUP_RE = re.compile(
    r"^https?://(?:"
    r"ipinfo\.io/ip"
    r"|ifconfig\.me(?:/ip)?"
    r"|icanhazip\.com/?"
    r"|checkip\.amazonaws\.com/?"
    r"|api\.ipify\.org/?"
    r"|ident\.me/?"
    r"|ipecho\.net/plain"
    r")(?:[?#].*)?$",
    re.IGNORECASE,
)
_OIDC_OAUTH_METADATA_URL_RE = re.compile(
    r"/\.well-known/(?:openid-configuration|oauth-authorization-server)(?:[?#/]|$)",
    re.IGNORECASE,
)
_CLOUD_METADATA_URL_RE = re.compile(
    r"^https?://(?:"
    r"169\.254\.169\.254/(?:metadata|latest/meta-data|computeMetadata/v1)"
    r"|metadata\.google\.internal/computeMetadata/v1"
    r")(?:[/?#]|$)",
    re.IGNORECASE,
)
_HEALTH_STATUS_PATH_RE = re.compile(
    r"/(?:api/health|healthz?|healthcheck|status)(?:[/?#]|$)",
    re.IGNORECASE,
)
_STATIC_WEB_ASSET_URL_RE = re.compile(
    r"\.(?:html?|css|png|jpe?g|gif|svg|ico|webp)(?:[?#]|$)",
    re.IGNORECASE,
)
_CURL_STATUS_WRITE_OUT_RE = re.compile(
    r"(?:^|\s)(?:-w|--write-out)(?:=|\s+)['\"]?%\{http_code\}",
    re.IGNORECASE,
)
_CURL_DATA_RE = re.compile(
    r"(?:^|\s)(?:--data(?:-[\w-]+)?|-d)(?:=|\s+)",
    re.IGNORECASE,
)
_APT_REPO_LIST_CONTEXT_RE = re.compile(
    r"\b(?:add-apt-repository|sources\.list(?:\.d)?|apt-key|gpg\s+--dearmor)\b",
    re.IGNORECASE,
)
_YUM_REPO_CONFIG_CONTEXT_RE = re.compile(
    r"(?:/etc/yum\.repos\.d/|\byum-config-manager\b|\bdnf\s+config-manager\b)",
    re.IGNORECASE,
)
_APT_REPO_LIST_URL_RE = re.compile(r"\.(?:list|repo)(?:[?#].*)?$", re.IGNORECASE)
_APT_REPO_PACKAGE_URL_RE = re.compile(
    r"https?://packages\.microsoft\.com/config/.+\.deb(?:[?#]|$)",
    re.IGNORECASE,
)
_APT_REPO_PACKAGE_INSTALL_RE = re.compile(
    r"\b(?:dpkg\s+-i|dpkg_install)\b[^\n]*(?:packages-microsoft-prod|mssql-release|ms)\S*\.deb",
    re.IGNORECASE,
)
_SIGNING_KEY_URL_RE = re.compile(
    r"(?:/(?:keys?|gpgkey)/|/(?:gpg|pubkey)(?:[?#]|$)|[/.][^/?#]*(?:keyring|pubkey|archive-key|repo)[^/?#]*\.(?:asc|gpg|key|pub)|\.(?:asc|gpg|key|pub)(?:[?#]|$))",
    re.IGNORECASE,
)
_VARIABLE_SIGNING_KEY_DEP_RE = re.compile(
    r"""^(?:"?\$\{[A-Za-z_][A-Za-z0-9_]*\}"?|\$[A-Za-z_][A-Za-z0-9_]*)(?:/|$)"""
)
_SIGNING_KEY_CONTEXT_RE = re.compile(
    r"(?:apt-key\b|gpg\s+--dearmor|/etc/apt/(?:keyrings|trusted\.gpg\.d)/|/usr/share/keyrings/|/etc/apk/keys/|"
    r"(?:^|\s)(?:-o|-O|--output(?:=|\s+)|--output-document(?:=|\s+))\s*['\"]?[^'\"\s]+\.(?:asc|gpg|key|pub)(?:['\"]|\s|$))",
    re.IGNORECASE,
)
_CLOUD_CP_COMMAND_RE = re.compile(r"\b(?:aws\s+s3\s+cp|gsutil\s+cp)\b", re.IGNORECASE)
_CLOUD_CP_VALUE_FLAGS = frozenset({
    "--acl",
    "--cache-control",
    "--content-disposition",
    "--content-encoding",
    "--content-language",
    "--content-type",
    "--endpoint-url",
    "--exclude",
    "--expires",
    "--include",
    "--metadata",
    "--metadata-directive",
    "--profile",
    "--region",
    "--sse",
    "--sse-c",
    "--sse-c-copy-source",
    "--sse-c-copy-source-key",
    "--sse-c-key",
    "--sse-kms-key-id",
    "--storage-class",
})
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
_BINARY_MARKDOWN_COMMAND_RE = re.compile(
    r"(?<![$\w.-])(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|DownloadFile|aria2c?|gh\s+release\s+download|aws\s+s3\s+cp|gsutil\s+cp|"
    r"(?:npx\s+|python\s+-m\s+|(?:npm|pnpm|yarn)\s+exec\s+)?playwright(?:-core)?\s+install|"
    r"(?:(?:npx|pnpm|yarn)\s+|(?:npm|pnpm|yarn)\s+exec\s+(?:--no\s+)?(?:--\s+)?)?"
    r"(?:puppeteer(?:-core)?\s+browsers|@puppeteer/browsers)\s+install)\b",
    re.IGNORECASE,
)
_REMOTE_SCRIPT_PIPE_RE = re.compile(
    r"\b(?:curl|wget)\b[^\n|]*?\|\s*(?:sudo\s+)?(?:bash|sh|zsh|dash)\b",
    re.IGNORECASE,
)
_JS_URL_CONST_ASSIGN_RE = re.compile(
    r"\b(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*(?P<expr>[^;]+)",
)
_JS_URL_CONST_START_RE = re.compile(
    r"\b(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*(?://.*)?$",
)
_JS_NODE_HTTP_IMPORT_RE = re.compile(
    r"(?:"
    r"\bfrom\s+['\"](?:node:)?(?:https?|http)['\"]"
    r"|require\(\s*['\"](?:node:)?(?:https?|http)['\"]\s*\)"
    r"|\b(?:https?|http)\s*\.\s*(?:get|request)\s*\("
    r")",
    re.IGNORECASE,
)
_JS_NODE_HTTP_BINARY_SINK_RE = re.compile(
    r"\b(?:Buffer\.concat|createWriteStream|writeFileSync|chmodSync)\b"
    r"|\bfs\.(?:createWriteStream|writeFileSync)\b",
    re.IGNORECASE,
)
_JS_NODE_HTTP_CALL_RE = re.compile(
    r"(?:"
    r"\b(?:https?|http)\s*\.\s*(?:get|request)"
    r"|(?<![\w$.])(?:get|request|fetch|fetchWithRetry|download(?:File|Binary)?)"
    r")\s*\(",
    re.IGNORECASE,
)
_JS_NODE_HTTP_LITERAL_URL_RE = re.compile(
    r"(?:"
    r"\b(?:https?|http)\s*\.\s*(?:get|request)"
    r"|(?<![\w$.])(?:get|request|fetch|fetchWithRetry|download(?:File|Binary)?)"
    r")\s*\(\s*['\"`](?P<dep>https?://(?!" + _LOCALHOST + r")[^'\"`\s]+)['\"`]",
    re.IGNORECASE,
)
_JS_HTTP_CLIENT_BINARY_CALL_RE = re.compile(
    r"\b(?:got|ky\.get|fetch|axios\.get)\s*\([^\n;]*\)"
    r"(?:\s*\.\s*(?:buffer|arrayBuffer|blob)\s*\(|[^\n;]*\bresponseType\s*:\s*['\"](?:arraybuffer|stream|blob)['\"])",
    re.IGNORECASE,
)
_JS_HTTP_CLIENT_LITERAL_BINARY_URL_RE = re.compile(
    r"\b(?:got|ky\.get|fetch|axios\.get)\s*\(\s*['\"`](?P<dep>https?://(?!" + _LOCALHOST + r")[^'\"`\s]+)['\"`]"
    r"[^\n;]*\)"
    r"(?:\s*\.\s*(?:buffer|arrayBuffer|blob)\s*\(|[^\n;]*\bresponseType\s*:\s*['\"](?:arraybuffer|stream|blob)['\"])",
    re.IGNORECASE,
)
_JS_DOWNLOAD_HELPER_CALL_RE = re.compile(
    r"(?<![\w$.])(?P<name>download(?:File(?:FromUrl)?|Binary)?|fetchWithRetry)\s*\("
    r"\s*(?P<src>[^,\)]+)"
    r"(?:,\s*(?P<dest>[^,\)]+))?",
    re.IGNORECASE,
)
_JS_OBJECT_CONST_START_RE = re.compile(
    r"^\s*const\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*\{\s*(?://.*)?$"
)
_JS_OBJECT_STRING_PROP_RE = re.compile(
    r"\b(?P<prop>[A-Za-z_$][\w$]*)\s*:\s*['\"](?P<value>[^'\"]+)['\"]"
)
_JS_OBJECT_INDEX_ALIAS_RE = re.compile(
    r"\b(?:const|let|var)\s+(?P<alias>[A-Za-z_$][\w$]*)\s*=\s*"
    r"(?P<object>[A-Za-z_$][\w$]*)\s*\[[^\]]+\]\s*;?"
)
_JS_TEMPLATE_OBJECT_PROP_RE = re.compile(
    r"\$\{\s*(?P<object>[A-Za-z_$][\w$]*)\.(?P<prop>[A-Za-z_$][\w$]*)\s*\}"
)
_MAX_JS_TEMPLATE_EXPANSIONS = 50
_POWERSHELL_URL_ASSIGN_RE = re.compile(
    r"(?P<var>\$(?:[A-Za-z_][A-Za-z0-9_]*:)?[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"['\"](?P<url>https?://(?!" + _LOCALHOST + r")[^'\"\s]+)['\"]",
    re.IGNORECASE,
)
_POWERSHELL_VAR_RE = re.compile(r"\$(?:[A-Za-z_][A-Za-z0-9_]*:)?[A-Za-z_][A-Za-z0-9_]*")
_POWERSHELL_WEBCLIENT_DOWNLOADFILE_RE = re.compile(
    r"\.DownloadFile\s*\(\s*(?P<src>[^,\)]+)",
    re.IGNORECASE,
)
_POWERSHELL_WEB_CMDLET_DOWNLOAD_RE = re.compile(
    r"\b(?:Invoke-WebRequestWithProxyDetection|Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\b(?P<body>[^\n]*?)"
    r"(?:-OutFile\b|-o\b)",
    re.IGNORECASE,
)
_POWERSHELL_WEB_CMDLET_RE = re.compile(
    r"\b(?:Invoke-WebRequestWithProxyDetection|Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\b(?P<body>[^\n]*)",
    re.IGNORECASE,
)
_POWERSHELL_LITERAL_WEB_DOWNLOAD_RE = re.compile(
    r"\b(?:Invoke-WebRequestWithProxyDetection|Invoke-WebRequest(?:-[A-Za-z][A-Za-z0-9]*)?|"
    r"iwr|Invoke-RestMethod|irm)\b(?P<body>.*?)(?:-OutFile\b|-o\b)",
    re.IGNORECASE,
)
_POWERSHELL_BITS_TRANSFER_RE = re.compile(
    r"\bStart-BitsTransfer\b(?P<body>[^\n]*)",
    re.IGNORECASE,
)
_POWERSHELL_DYNAMIC_DOWNLOAD_PROP_RE = re.compile(
    r"(?P<dep>\$[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*"
    r"\.(?:browser_download_url|archive_download_url|download_url))\b",
    re.IGNORECASE,
)
_POWERSHELL_DYNAMIC_NUGET_URL_VAR_RE = re.compile(
    r"\$(?:[A-Za-z_][A-Za-z0-9_]*:)?(?=[A-Za-z_])"
    r"[A-Za-z0-9_]*nuget[A-Za-z0-9_]*download[A-Za-z0-9_]*(?:url|uri)[A-Za-z0-9_]*",
    re.IGNORECASE,
)
_POWERSHELL_OUTFILE_ARG_RE = re.compile(
    r"(?:-OutFile\b|-o\b)\s+"
    r"(?P<dest>\"[^\"]+\"|'[^']+'|`[^`]+`|[^\s;|]+)",
    re.IGNORECASE,
)
_POWERSHELL_FUNCTION_START_RE = re.compile(
    r"^\s*function\s+(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\b[^{]*\{",
    re.IGNORECASE,
)
_POWERSHELL_FUNCTION_DECL_RE = re.compile(
    r"^\s*function\s+(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\b",
    re.IGNORECASE,
)
_POWERSHELL_DOWNLOAD_HELPER_NAME_RE = re.compile(r"download|fetch|get", re.IGNORECASE)
_POWERSHELL_DOWNLOAD_HELPER_BODY_RE = re.compile(
    r"\.DownloadFile\s*\("
    r"|\b(?:Invoke-WebRequestWithProxyDetection|Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\b[^\n]*?(?:-OutFile\b|-o\b)"
    r"|\b(?:curl|wget)\b[^\n]*?(?:-(?=(?-i:[A-Za-z]*[oO])(?:\s|$))[A-Za-z]+|--output|--remote-name|-O\b)",
    re.IGNORECASE,
)
_PY_IDENTIFIER = r"[A-Za-z_][A-Za-z0-9_]*"
_PY_URLISH_PARAM_RE = re.compile(r"(?:^|_)(?:url|uri)(?:_|$)", re.IGNORECASE)
_PY_DOWNLOAD_SOURCE_PARAM_RE = re.compile(r"(?:^|_)source(?:_|$)", re.IGNORECASE)
_PY_URL_LITERAL_ASSIGN_RE = re.compile(
    r"(?P<var>" + _PY_IDENTIFIER + r")\s*=\s*['\"](?P<url>https?://(?!" + _LOCALHOST + r")[^'\"\s]+)['\"]",
    re.IGNORECASE,
)
_PY_URL_DEFAULT_ARG_RE = re.compile(
    r"(?P<var>" + _PY_IDENTIFIER + r")\s*=\s*['\"](?P<url>https?://(?!" + _LOCALHOST + r")[^'\"\s]+)['\"]",
    re.IGNORECASE,
)
_PY_URL_ALIAS_ASSIGN_RE = re.compile(
    r"(?P<var>" + _PY_IDENTIFIER + r")\s*=\s*(?P<src>" + _PY_IDENTIFIER + r")\s*(?:#.*)?$",
)
_PY_URL_ENV_FALLBACK_RE = re.compile(
    r"(?P<var>" + _PY_IDENTIFIER + r")\s*=\s*[^#\n]*\benviron\.get\s*\([^,\n]+,\s*(?P<src>" + _PY_IDENTIFIER + r")\s*\)",
)
_PY_URLRETRIEVE_RE = re.compile(
    r"\b(?:urllib\.request\.)?urlretrieve\s*\(\s*(?P<src>[^,\)]+)(?:,\s*(?P<dest>[^,\)]+))?",
    re.IGNORECASE,
)
_PY_WGET_DOWNLOAD_RE = re.compile(
    r"\bwget\.download\s*\(\s*(?P<src>[^,\)]+)(?:,\s*(?:out\s*=\s*)?(?P<dest>[^\n#]+))?",
    re.IGNORECASE,
)
_PY_SUPER_INIT_URL_FORWARD_RE = re.compile(
    r"\bsuper\s*\([^\n)]*\)\s*\.\s*__init__\s*\([^\n#]*"
    r"\b(?:url|uri)\s*=\s*(?P<src>(?:self\.)?" + _PY_IDENTIFIER + r"(?:\." + _PY_IDENTIFIER + r")*)",
    re.IGNORECASE,
)
_PY_REQUESTS_STREAM_GET_RE = re.compile(
    r"\brequests\.get\s*\(\s*(?P<src>[^,\)]+)[^\n]*\bstream\s*=\s*True\b",
    re.IGNORECASE,
)
_PY_TORCH_LOAD_STATE_DICT_RE = re.compile(
    r"\b(?:torch\.hub\.)?load_state_dict_from_url\s*\(\s*(?P<src>[^,\)]+)",
    re.IGNORECASE,
)
_PY_DICT_ASSIGN_START_RE = re.compile(r"^\s*(?P<var>" + _PY_IDENTIFIER + r")\s*=\s*\{\s*(?:#.*)?$")
_PY_DICT_URL_ENTRY_RE = re.compile(
    r"^\s*[^#:\n]+:\s*['\"](?P<url>https?://(?!" + _LOCALHOST + r")[^'\"\s]+)['\"]",
    re.IGNORECASE,
)
_PY_BINARY_DEST_HINT_RE = re.compile(
    r"(?:zip|tar|tgz|gz|bz2|xz|7z|archive|artifact|package|nupkg|vsix|checkpoint|weights?|model|onnx)",
    re.IGNORECASE,
)
_PY_DYNAMIC_DOWNLOAD_KEYS = frozenset({"archive_download_url", "browser_download_url", "download_url"})
_PYTHON_DIRECT_DOWNLOAD_PATTERN_IDS = frozenset({
    "python-package-url-install",
    "python-requests-content-download",
    "python-requests-stream-download",
    "python-torch-model-download",
    "python-urlretrieve-download",
    "python-wget-download",
    "python-wget-tool-download",
})
_DOCKERFILE_ADD_REMOTE_URL_RE = re.compile(
    r"^\s*ADD\s+"
    r"(?:--[A-Za-z][\w-]*(?:=\S+)?\s+)*"
    r"(?:\[\s*)?['\"]?(?P<dep>https?://(?!" + _LOCALHOST + r")[^'\"\s,\]]+)",
    re.IGNORECASE,
)
_ARCHIVE_PIPE_DOWNLOAD_RE = re.compile(
    r"\b(?:curl|wget)\b[^\n|]*?"
    r"(?P<dep>https?://(?!" + _LOCALHOST + r")[^'\"\s|)]+)"
    r"[^\n|]*\|\s*(?:tar|bsdtar)\b",
    re.IGNORECASE,
)
_SOURCE_ARCHIVE_PIPE_DOWNLOAD_RE = re.compile(
    r"\b(?:curl|wget)\b(?P<body>[^`'\"\n|;]*?)\|\s*(?:tar|bsdtar)\b",
    re.IGNORECASE,
)
_SOURCE_TEMPLATE_EXPR_RE = re.compile(r"\$\{\s*(?P<expr>[^}]+?)\s*\}")
_SOURCE_IDENTIFIER_RE = re.compile(r"\b[A-Za-z_$][\w$]*\b")
_BINARY_ARTIFACT_URL_HINT_RE = re.compile(
    r"(?:"
    r"/releases/download/"
    r"|/downloads?/"
    r"|/artifacts?/"
    r"|/files/\d+(?:[/?#}`\"']|$)"
    r"|[/.](?:"
    r"zip|tar|tar\.gz|tgz|tar\.xz|tar\.bz2|tbz2|7z|rar|gz|xz|bz2"
    r"|exe|msi|pkg|dmg|deb|rpm|apk|appimage|bin|ova"
    r"|jar|war|nupkg|vsix|wasm|whl"
    r"|pth|pt|onnx|safetensors|ckpt|pb|tflite|npz|pkl|joblib"
    r")(?:[/?#}`\"']|$)"
    r"|\$\{[^}]*asset[^}]*\}"
    r")",
    re.IGNORECASE,
)


class BinaryDownloadScanner(BaseScanner):
    name = "binary-downloads"

    def scan_file(self, target: FileTarget) -> list[Finding]:
        applicable = [r for r in self._rules if "*" in r.file_types or target.file_type in r.file_types]
        if not applicable and target.file_type != "source_code":
            return []
        try:
            content = target.path.read_text(errors="replace")
        except OSError:
            return []
        return self.scan_file_content(target, content, content.splitlines())

    def scan_file_content(self, target: FileTarget, content: str, lines: list[str]) -> list[Finding]:
        findings = super().scan_file_content(target, content, lines)
        findings.extend(self._scan_source_shell_binary_downloads(target, content, lines, findings))
        findings.extend(self._scan_source_embedded_archive_pipe_downloads(target, lines, findings))
        findings.extend(_scan_javascript_node_http_binary_downloads(target, content, lines, findings))
        findings.extend(_scan_python_binary_download_apis(target, lines, findings))
        findings.extend(_scan_python_requests_content_downloads(target, content, lines, findings))
        findings.extend(_scan_python_download_helper_call_urls(target, content, lines, findings))
        findings.extend(_scan_python_package_url_installs(target, content, lines, findings))
        findings.extend(_scan_python_wget_tool_downloads(target, content, lines, findings))
        findings.extend(_scan_python_huggingface_artifact_downloads(target, content, findings))
        findings.extend(_scan_dockerfile_huggingface_literal_loads(target, lines, findings))
        findings.extend(_scan_powershell_variable_binary_downloads(target, lines, findings))
        findings.extend(_scan_powershell_literal_web_downloads(target, lines, findings))
        findings.extend(_scan_dockerfile_add_remote_binary_downloads(target, lines, findings))
        findings.extend(_scan_archive_pipe_binary_downloads(target, lines, findings))
        findings.extend(_scan_nuget_package_downloads(target, lines, findings))
        findings.extend(_scan_playwright_browser_installs(target, lines, findings))
        findings.extend(_scan_puppeteer_browser_installs(target, lines, findings))
        findings = _normalize_url_dependency_findings(findings)
        findings = _normalize_gh_release_dependency_findings(findings)
        findings = _resolve_variable_url_download_findings(lines, findings)
        findings = [
            finding for finding in findings
            if not _is_non_binary_download_call(finding)
            and not _is_apt_repo_package_config_download(finding, lines)
            and not _is_jsonc_commented_binary_download_line(target, lines, finding.line_number, finding.extracted_dep)
            and not _is_powershell_block_comment_line(target, lines, finding.line_number)
            and not _is_powershell_metadata_string_download_line(target, lines, finding)
            and not _is_non_control_markdown_binary_download_example(target, finding, lines)
            and not is_placeholder_url_dependency(finding.extracted_dep)
            and not _is_placeholder_cloud_storage_dependency(finding)
            and not _is_placeholder_url_variable_download(finding, lines)
            and not _is_reserved_example_url_in_test_fixture_path(target, finding)
        ]
        literal_download_lines = {
            f.line_number for f in findings
            if f.pattern_id in {"curl-download", "curl-download-url-first", "github-release-download", "wget-download"}
        }
        if not literal_download_lines:
            return _dedupe_findings_by_file_dependency(findings)
        findings = [
            f for f in findings
            if not (f.pattern_id in {"curl-var-download", "wget-var-download"} and f.line_number in literal_download_lines)
        ]
        return _dedupe_findings_by_file_dependency(findings)

    def _scan_source_shell_binary_downloads(
        self,
        target: FileTarget,
        content: str,
        lines: list[str],
        existing: list[Finding],
    ) -> list[Finding]:
        if target.file_type != "source_code":
            return []
        existing_keys = {
            (finding.line_number, finding.pattern_id, finding.extracted_dep)
            for finding in existing
        }
        added: list[Finding] = []
        shell_target = FileTarget(path=target.path, rel_path=target.rel_path, file_type="script")
        commands = [
            *iter_python_shell_commands(target, content, lines),
            *iter_javascript_shell_commands(target, content, lines),
        ]
        for command in commands:
            if _REMOTE_SCRIPT_PIPE_RE.search(command.command):
                continue
            for finding in super().scan_file_content(shell_target, command.command, [command.command]):
                key = (command.line_number, finding.pattern_id, finding.extracted_dep)
                if key in existing_keys:
                    continue
                finding.line_number = command.line_number
                finding.matched_text = command.command[:200]
                added.append(finding)
                existing_keys.add(key)
        return added

    def _scan_source_embedded_archive_pipe_downloads(
        self,
        target: FileTarget,
        lines: list[str],
        existing: list[Finding],
    ) -> list[Finding]:
        if target.file_type != "source_code" or _is_test_source_path(target.rel_path):
            return []

        existing_keys = {
            (finding.line_number, finding.pattern_id, finding.extracted_dep)
            for finding in existing
        }
        added: list[Finding] = []
        for line_number, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("//", "#", "*")):
                continue
            for match in _SOURCE_ARCHIVE_PIPE_DOWNLOAD_RE.finditer(line):
                dep = _extract_source_archive_pipe_dep(match.group("body"))
                if not dep:
                    continue
                key = (line_number, "archive-pipe-download", dep)
                if key in existing_keys:
                    continue
                added.append(Finding(
                    file_path=target.rel_path,
                    line_number=line_number,
                    category=Category.BINARY_DOWNLOAD,
                    severity=Severity.HIGH,
                    pattern_id="archive-pipe-download",
                    matched_text=stripped[:200],
                    extracted_dep=dep[:200],
                    description=f"Source-code shell archive download piped to tar: {dep[:200]}",
                    scanner_name=BinaryDownloadScanner.name,
                ))
                existing_keys.add(key)
        return added

    def register_rules(self) -> None:
        # curl -o <file> <url> (flag before URL)
        self.add_rule(PatternRule(
            pattern_id="curl-download",
            regex=re.compile(
                r"curl(?:\.exe)?\b[^|;&\n]*?"
                r"(?:-(?=(?-i:[A-Za-z]*o)(?:\s|$))[A-Za-z]+|--output(?:=|\s+))\s*\S+"
                r"[^|;&\n]*?(?P<dep>" + _URL_TOKEN + r")",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Direct binary download via curl: {dep}",
            category=Category.BINARY_DOWNLOAD,
            file_types=_FT,
            multiple=True,
        ))

        # curl <url> -o <file> (URL before flag)
        self.add_rule(PatternRule(
            pattern_id="curl-download-url-first",
            regex=re.compile(
                r"curl(?:\.exe)?\b[^|;&\n]*?(?P<dep>" + _URL_TOKEN + r")[^|;&\n]*?"
                r"(?:-(?=(?-i:[A-Za-z]*o)(?:\s|$))[A-Za-z]+|--output(?:=|\s+))\s*\S+",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Direct binary download via curl: {dep}",
            category=Category.BINARY_DOWNLOAD,
            file_types=_FT,
            multiple=True,
        ))

        # curl -fsSLO <url> or curl -SLO --output-dir <dir> <url>.
        # Uppercase -O/--remote-name uses the remote filename and does not
        # take a local output argument.
        self.add_rule(PatternRule(
            pattern_id="curl-download",
            regex=re.compile(
                r"curl(?:\.exe)?\b"
                r"(?=[^|;&\n]*?(?:-(?=(?-i:[A-Za-z]*O)\b)[A-Za-z]+|--remote-name\b))"
                r"[^|;&\n]*?(?P<dep>" + _URL_TOKEN + r")",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Direct binary download via curl: {dep}",
            category=Category.BINARY_DOWNLOAD,
            file_types=_FT,
            multiple=True,
        ))

        # wget -O <file> <url> or wget <url> -O <file>
        self.add_rule(PatternRule(
            pattern_id="wget-download",
            regex=re.compile(
                r"wget\b[^\n]*?(?P<dep>" + _URL_TOKEN + r")",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Direct download via wget: {dep}",
            category=Category.BINARY_DOWNLOAD,
            file_types=_FT,
        ))

        # wget -O /tmp/tool "$BASE_URL/tool" — variable-constructed URL.
        self.add_rule(PatternRule(
            pattern_id="wget-var-download",
            regex=re.compile(
                r"wget\b[^\n]*?(?:-O\s+\S+|--output-document(?:=|\s+)\S+)"
                r"[^\n]*?['\"]?(?P<dep>" + _URLISH_VAR + r")",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Direct download via wget with variable URL: {dep}",
            category=Category.BINARY_DOWNLOAD,
            file_types=_FT,
        ))

        # wget "$URL" -O /tmp/tool — variable URL before output flag.
        self.add_rule(PatternRule(
            pattern_id="wget-var-download",
            regex=re.compile(
                r"wget\b[^\n]*?['\"]?(?P<dep>" + _URLISH_VAR + r")"
                r"[^\n]*?(?:-O\s+\S+|--output-document(?:=|\s+)\S+)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Direct download via wget with variable URL: {dep}",
            category=Category.BINARY_DOWNLOAD,
            file_types=_FT,
        ))

        # wget "$URL" -P /tmp or wget -P /tmp "$URL" downloads to a directory.
        self.add_rule(PatternRule(
            pattern_id="wget-var-download",
            regex=re.compile(
                r"wget\b[^\n]*?(?:-P\s+\S+|--directory-prefix(?:=|\s+)\S+)"
                r"[^\n]*?['\"]?(?P<dep>" + _URLISH_VAR + r")",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Direct download via wget with variable URL: {dep}",
            category=Category.BINARY_DOWNLOAD,
            file_types=_FT,
        ))

        self.add_rule(PatternRule(
            pattern_id="wget-var-download",
            regex=re.compile(
                r"wget\b[^\n]*?['\"]?(?P<dep>" + _URLISH_VAR + r")"
                r"[^\n]*?(?:-P\s+\S+|--directory-prefix(?:=|\s+)\S+)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Direct download via wget with variable URL: {dep}",
            category=Category.BINARY_DOWNLOAD,
            file_types=_FT,
        ))

        # wget "$URL" downloads to a local file by default even without -O/-P.
        # Keep this variable-only and rely on resolution to concrete artifact
        # URLs so status checks and metadata probes do not become findings.
        self.add_rule(PatternRule(
            pattern_id="wget-var-download",
            regex=re.compile(
                r"wget\b"
                r"(?![^\n]*?(?:--spider\b|-[A-Za-z]*O(?:\s+|-)|--output-document(?:=|\s+)(?:-|/dev/null)|-O\s*/dev/null))"
                r"[^\n]*?['\"]?(?P<dep>" + _URLISH_VAR + r")",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Direct download via wget with variable URL: {dep}",
            category=Category.BINARY_DOWNLOAD,
            file_types=_FT,
        ))

        # curl.exe -o $DestinationPath $Url — variable-constructed URL.
        self.add_rule(PatternRule(
            pattern_id="curl-var-download",
            regex=re.compile(
                r"curl(?:\.exe)?\b(?![^\n]*?/dev/null)[^\n]*?"
                r"(?:"
                r"-(?=(?-i:[A-Za-z]*o)(?:\s|$))[A-Za-z]+\s+\S+"
                r"|--output(?:=|\s+)\S+"
                r")"
                r"[^\n]*?['\"]?(?P<dep>" + _URLISH_VAR + r")",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Direct download via curl with variable URL: {dep}",
            category=Category.BINARY_DOWNLOAD,
            file_types=_FT,
        ))

        # curl "$URL" -o <file> or curl -SLO "$BASE_URL/file".
        self.add_rule(PatternRule(
            pattern_id="curl-var-download",
            regex=re.compile(
                r"curl(?:\.exe)?\b(?![^\n]*?/dev/null)[^\n]*?['\"]?(?P<dep>" + _URLISH_VAR + r")"
                r"[^\n]*?(?:"
                r"-(?=(?-i:[A-Za-z]*o)(?:\s|$))[A-Za-z]+\s+\S+"
                r"|--output(?:=|\s+)\S+"
                r"|-(?=(?-i:[A-Za-z]*O)\b)[A-Za-z]+"
                r"|--remote-name\b"
                r")",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Direct download via curl with variable URL: {dep}",
            category=Category.BINARY_DOWNLOAD,
            file_types=_FT,
        ))

        self.add_rule(PatternRule(
            pattern_id="curl-var-download",
            regex=re.compile(
                r"curl(?:\.exe)?\b(?![^\n]*?/dev/null)"
                r"(?=[^\n]*?(?:-(?=(?-i:[A-Za-z]*O)\b)[A-Za-z]+|--remote-name\b))"
                r"[^\n]*?['\"]?(?P<dep>" + _URLISH_VAR + r")",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Direct download via curl with variable URL: {dep}",
            category=Category.BINARY_DOWNLOAD,
            file_types=_FT,
        ))

        # SCRIPT=$(curl https://...) followed by later execution is a shadow
        # download even before the execution site is resolved.
        self.add_rule(PatternRule(
            pattern_id="curl-assigned-download",
            regex=re.compile(
                r"\b[A-Za-z_][A-Za-z0-9_]*=\$\(\s*curl\b[^\n)]*?"
                r"(?:\s|['\"])(?P<dep>" + _CURL_ASSIGNED_URL_TOKEN + r")",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="curl download assigned to variable for later execution: {dep}",
            category=Category.BINARY_DOWNLOAD,
            file_types=_FT,
        ))

        # Repo-local download helpers can hide literal artifact URLs from the
        # scanner because the actual curl/wget call receives only a variable.
        self.add_rule(PatternRule(
            pattern_id="download-helper-url",
            regex=re.compile(
                r"(?:^|\s)[^\s]*download[\w.-]*\.ps1\b"
                r"[^\n]*?\s-(?:Url|Uri)\s+['\"](?P<dep>https?://(?!" + _LOCALHOST + r")[^'\"]+)['\"]",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Download helper receives external artifact URL: {dep}",
            category=Category.BINARY_DOWNLOAD,
            file_types=_FT,
        ))

        # GitHub releases specifically (curl or wget targeting /releases/download/)
        self.add_rule(PatternRule(
            pattern_id="github-release-download",
            regex=re.compile(
                r"(?:curl|wget)\b[^\n]*?(?P<dep>" + _GITHUB_RELEASE_URL_TOKEN + r")",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="GitHub release binary download: {dep}",
            category=Category.BINARY_DOWNLOAD,
            file_types=_FT,
        ))

        # gh release download
        self.add_rule(PatternRule(
            pattern_id="gh-release-download",
            regex=re.compile(
                r"gh\s+release\s+download\b"
                r"(?:\s+(?:(?:-R|--repo|-D|--dir|-p|--pattern)\s+\S+|--\S+))*"
                r"\s+(?P<dep>(?!-)\S+)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="GitHub CLI release download: {dep}",
            category=Category.BINARY_DOWNLOAD,
            file_types=_FT,
        ))

        # Cloud storage downloads (S3, GCS, Azure Blob) via CLI tools
        # Only capture the cloud URI (s3://, gs://) not local file paths
        self.add_rule(PatternRule(
            pattern_id="cloud-storage-download",
            regex=re.compile(
                r"(?:aws\s+s3\s+cp|gsutil\s+cp|az\s+storage\s+blob\s+download)\s+"
                r"(?:\S+\s+)*?"
                r"(?P<dep>s3://[^`'\"\s|)]+|gs://[^`'\"\s|)]+)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Binary downloaded from cloud storage: {dep}",
            category=Category.BINARY_DOWNLOAD,
            file_types=_FT,
        ))

        # chmod +x on a downloaded file (multiline: download then chmod)
        self.add_rule(PatternRule(
            pattern_id="chmod-downloaded-binary",
            regex=re.compile(
                r"(?:curl|wget)\b(?![^\n]*" + _NULL_OUTPUT_TOKEN + r")[^\n]*?"
                r"(?P<dep>" + _URL_TOKEN + r")[^\n]*"
                r"(?:"
                r"chmod\s+\+x"
                r"|\n(?:(?!\s*(?:FROM|RUN|CMD|LABEL|MAINTAINER|EXPOSE|ENV|ADD|COPY|ENTRYPOINT|VOLUME|USER|WORKDIR|ARG|ONBUILD|STOPSIGNAL|HEALTHCHECK|SHELL)\b)[^\n]*\n){0,5}[^\n]*chmod\s+\+x"
                r")",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Downloaded file made executable (chmod +x): {dep}",
            category=Category.BINARY_DOWNLOAD,
            file_types=_FT,
            multiline=True,
        ))

        # --- PowerShell download mechanisms ---

        # Invoke-WebRequest -Uri <url> -OutFile <file>
        self.add_rule(PatternRule(
            pattern_id="powershell-invoke-webrequest",
            regex=re.compile(
                r"(?:Invoke-WebRequestWithProxyDetection|Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\s+[^\n]*?(?:-Uri\s+)?['\"]?(?P<dep>https?://\S+?)['\"]?(?:\s+-OutFile|\s+-o\b)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="PowerShell download via Invoke-WebRequest: {dep}",
            category=Category.BINARY_DOWNLOAD,
            file_types=_ALL_SCRIPTABLE,
        ))

        # Start-BitsTransfer
        self.add_rule(PatternRule(
            pattern_id="powershell-bits-transfer",
            regex=re.compile(
                r"Start-BitsTransfer\s+[^\n]*?-Source\s+['\"]?(?P<dep>https?://\S+?)['\"]?",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="PowerShell download via Start-BitsTransfer: {dep}",
            category=Category.BINARY_DOWNLOAD,
            file_types=_ALL_SCRIPTABLE,
        ))

        # bitsadmin /TRANSFER <job> /DOWNLOAD ... <url> <dest>
        self.add_rule(PatternRule(
            pattern_id="bitsadmin-download",
            regex=re.compile(
                r"\bbitsadmin(?:\.exe)?\b[^\n]*?/DOWNLOAD\b[^\n]*?['\"]?"
                r"(?P<dep>" + _URL_TOKEN + r")",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="Windows bitsadmin downloads binary/content: {dep}",
            category=Category.BINARY_DOWNLOAD,
            file_types=_ALL_SCRIPTABLE,
        ))

        # System.Net.WebClient DownloadFile
        self.add_rule(PatternRule(
            pattern_id="powershell-webclient-download",
            regex=re.compile(
                r"\.DownloadFile\s*\(\s*['\"](?P<dep>https?://\S+?)['\"]",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="PowerShell WebClient.DownloadFile: {dep}",
            category=Category.BINARY_DOWNLOAD,
            file_types=_ALL_SCRIPTABLE,
        ))

        # --- Other download tools ---

        # aria2c
        self.add_rule(PatternRule(
            pattern_id="aria2c-download",
            regex=re.compile(
                r"aria2c?\s+[^\n]*?(?P<dep>https?://\S+)",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="aria2c binary download: {dep}",
            category=Category.BINARY_DOWNLOAD,
            file_types=_FT,
        ))


def _is_non_binary_download_call(finding: Finding) -> bool:
    if finding.pattern_id not in {
        "curl-download",
        "curl-download-url-first",
        "github-release-download",
        "curl-assigned-download",
        "curl-var-download",
        "wget-download",
        "wget-var-download",
        "chmod-downloaded-binary",
        "cloud-storage-download",
        "powershell-invoke-webrequest",
        "powershell-webclient-download",
        "powershell-bits-transfer",
        "powershell-start-bitstransfer",
    }:
        return False
    text = finding.matched_text
    dep = finding.extracted_dep
    dep_clean = dep.strip("'\"")
    is_json_api = bool(_JSON_API_URL_RE.search(dep))
    if (
        _CHECKSUM_TEXT_URL_RE.search(dep_clean)
        and not _BINARY_ACCEPT_RE.search(text)
    ):
        return True
    if is_json_api and not _BINARY_ACCEPT_RE.search(text):
        return True
    if finding.pattern_id == "curl-assigned-download" and re.search(
        r"(?:^|\s)(?:-[A-Za-z]*[oO]\b|--output(?:=|\s))",
        text,
    ):
        return True
    if finding.pattern_id == "curl-assigned-download" and _CURRENT_IP_LOOKUP_RE.match(dep_clean):
        return True
    if finding.pattern_id == "curl-assigned-download" and _is_metadata_assignment(text, dep_clean):
        return True
    if finding.pattern_id == "curl-assigned-download" and _JSON_PARSE_PIPE_RE.search(text) and not _BINARY_ACCEPT_RE.search(text):
        return True
    if _CLOUD_METADATA_URL_RE.match(dep_clean) and not _BINARY_ACCEPT_RE.search(text):
        return True
    if _OIDC_OAUTH_METADATA_URL_RE.search(dep_clean) and not _BINARY_ACCEPT_RE.search(text):
        return True
    if _STATIC_WEB_ASSET_URL_RE.search(dep_clean) and not _BINARY_ACCEPT_RE.search(text):
        return True
    if _TEXT_METADATA_URL_RE.search(dep_clean) and not _BINARY_ACCEPT_RE.search(text):
        return True
    if _is_package_signing_key_download(text, dep_clean) and not _BINARY_ACCEPT_RE.search(text):
        return True
    if _curl_command_has_data_flag(text) and not _BINARY_ACCEPT_RE.search(text):
        return True
    if _CURL_STATUS_WRITE_OUT_RE.search(text) and _HEALTH_STATUS_PATH_RE.search(dep_clean):
        return True
    if (
        (_APT_REPO_LIST_CONTEXT_RE.search(text) or _YUM_REPO_CONFIG_CONTEXT_RE.search(text))
        and _APT_REPO_LIST_URL_RE.search(dep_clean)
    ):
        return True
    if finding.pattern_id in {"wget-download", "wget-var-download"} and (
        _WGET_NULL_OUTPUT_RE.search(text) or _WGET_SPIDER_RE.search(text)
    ):
        return True
    if (
        finding.pattern_id == "wget-download"
        and _WGET_STDOUT_OUTPUT_RE.search(text)
        and (_TEXT_METADATA_PIPE_RE.search(text) or _TEXT_METADATA_URL_RE.search(dep_clean))
    ):
        return True
    if _NULL_OUTPUT_RE.search(text):
        return True
    if finding.pattern_id == "cloud-storage-download" and _is_cloud_storage_upload_destination(text, dep_clean):
        return True
    if _JSON_OUTPUT_RE.search(text) or _YAML_METADATA_OUTPUT_RE.search(text) or _TEXT_METADATA_OUTPUT_RE.search(text):
        return True
    if _YAML_METADATA_URL_RE.search(dep_clean) and not _BINARY_ACCEPT_RE.search(text):
        return True
    if re.search(r"(?:^|\s)(?:-X|--request(?:=|\s))\s*(?:POST|PUT|PATCH|DELETE)\b", text, re.IGNORECASE):
        return True
    if re.search(r"\bContent-Type:\s*application/json\b", text, re.IGNORECASE):
        return True
    return False


def _is_package_signing_key_download(text: str, dep: str) -> bool:
    context = text.replace(dep, "")
    if not _SIGNING_KEY_CONTEXT_RE.search(context):
        return False
    return bool(_SIGNING_KEY_URL_RE.search(dep) or _VARIABLE_SIGNING_KEY_DEP_RE.search(dep))


def _is_apt_repo_package_config_download(finding: Finding, lines: list[str]) -> bool:
    dep = finding.extracted_dep.strip("'\"")
    if not _APT_REPO_PACKAGE_URL_RE.search(dep):
        return False
    if finding.line_number < 1:
        return False

    window_size = 85 if finding.pattern_id == "dockerfile-add-remote-binary" else 6
    start = max(finding.line_number - 1, 0)
    window = "\n".join(lines[start:start + window_size])
    return bool(_APT_REPO_PACKAGE_INSTALL_RE.search(window))


def _curl_command_has_data_flag(text: str) -> bool:
    match = re.search(r"\bcurl(?:\.exe)?\b", text, re.IGNORECASE)
    if not match:
        return bool(_CURL_DATA_RE.search(text))
    segment = re.split(r"\s*(?:&&|\|\||[;|])", text[match.start():], maxsplit=1)[0]
    return bool(_CURL_DATA_RE.search(segment))


def _is_metadata_assignment(text: str, url: str) -> bool:
    if _BINARY_ACCEPT_RE.search(text):
        return False
    match = _CURL_ASSIGNED_VAR_RE.search(text)
    assigned_var = match.group("var") if match else ""
    if _JSON_METADATA_URL_RE.search(url) or _CONTAINER_REGISTRY_METADATA_URL_RE.search(url):
        return True
    if _TEXT_METADATA_URL_RE.search(url) and _TEXT_METADATA_PIPE_RE.search(text):
        return True
    if not _METADATA_ASSIGNED_VAR_RE.search(assigned_var):
        return False
    return bool(_TEXT_METADATA_URL_RE.search(url) or _TEXT_METADATA_PIPE_RE.search(text))


def _is_cloud_storage_upload_destination(text: str, dep: str) -> bool:
    command = _CLOUD_CP_COMMAND_RE.search(text)
    dep_index = text.find(dep)
    if not command or dep_index == -1 or dep_index < command.end():
        return False
    prefix = text[command.start():dep_index]
    try:
        tokens = shlex.split(prefix)
    except ValueError:
        tokens = prefix.split()

    if len(tokens) < 2:
        return False
    start = 3 if len(tokens) >= 3 and tokens[0].lower() == "aws" and tokens[1].lower() == "s3" else 2
    operands = tokens[start:]
    skip_next = False
    for token in operands:
        if skip_next:
            skip_next = False
            continue
        if token.startswith("--"):
            flag = token.split("=", 1)[0]
            skip_next = "=" not in token and flag in _CLOUD_CP_VALUE_FLAGS
            continue
        if token.startswith("-"):
            continue
        return True
    return False


def _is_placeholder_url_variable_download(finding: Finding, lines: list[str]) -> bool:
    if finding.pattern_id not in {"curl-var-download", "wget-var-download"}:
        return False
    var = _pure_shell_variable_name(finding.extracted_dep)
    if not var or not (0 < finding.line_number <= len(lines)):
        return False
    assignment = _nearest_prior_url_assignment(lines[:finding.line_number - 1], var)
    return bool(assignment and is_placeholder_url_dependency(assignment))


def _resolve_variable_url_download_findings(lines: list[str], findings: list[Finding]) -> list[Finding]:
    concrete_keys = {
        (finding.line_number, finding.extracted_dep)
        for finding in findings
        if finding.pattern_id not in {"curl-var-download", "wget-var-download"}
        and re.match(r"^https?://", finding.extracted_dep, re.IGNORECASE)
    }
    resolved: list[Finding] = []
    for finding in findings:
        if finding.pattern_id not in {"curl-var-download", "wget-var-download"}:
            resolved.append(finding)
            continue
        dep = _resolve_variable_url_download_dep(lines, finding)
        if dep == finding.extracted_dep:
            resolved.append(finding)
            continue
        if (finding.line_number, dep) in concrete_keys:
            continue
        resolved.append(_replace_finding_dep(finding, dep))
    return resolved


def _resolve_variable_url_download_dep(lines: list[str], finding: Finding) -> str:
    if not (0 < finding.line_number <= len(lines)):
        return finding.extracted_dep
    var, suffix = _shell_variable_reference_parts(finding.extracted_dep)
    if not var:
        return finding.extracted_dep
    assignment = _nearest_prior_url_assignment(lines[:finding.line_number - 1], var)
    if not assignment or is_placeholder_url_dependency(assignment):
        return finding.extracted_dep
    return _normalize_url_dep(f"{assignment}{suffix}")


def _shell_variable_reference_parts(dep: str) -> tuple[str, str]:
    dep = dep.strip("'\"")
    batch_match = re.fullmatch(
        r"%(?P<var>[A-Za-z_][A-Za-z0-9_]*)%(?P<suffix>(?:[./_-][^'\"\s%]*)?)",
        dep,
    )
    if batch_match:
        return batch_match.group("var").lower(), batch_match.group("suffix") or ""
    match = re.fullmatch(
        r"\$\{?(?P<var>[A-Za-z_][A-Za-z0-9_]*)\}?(?P<suffix>(?:[./_-][^'\"\s$]*)?)",
        dep,
    )
    if not match:
        return "", ""
    return match.group("var").lower(), match.group("suffix") or ""


def _is_placeholder_cloud_storage_dependency(finding: Finding) -> bool:
    if finding.pattern_id != "cloud-storage-download":
        return False
    dep = finding.extracted_dep.strip("\"'`").lower()
    return bool(re.match(r"^(?:s3|gs)://my-[a-z0-9.-]*artifacts?(?:[/.]|$)", dep))


def _is_reserved_example_url_in_test_fixture_path(target: FileTarget, finding: Finding) -> bool:
    if target.file_type not in set(_ALL_SCRIPTABLE):
        return False
    path = "/" + target.rel_path.replace("\\", "/").lower()
    if not any(
        segment in path
        for segment in (
            "/test/",
            "/tests/",
            "/testing/",
            "/testdata/",
            "/fixture/",
            "/fixtures/",
            "/__fixtures__/",
        )
    ):
        return False
    return bool(re.match(
        r"^https?://(?:[^/?#@]+\.)?example\.(?:com|org|net)(?:[/:?#]|$)",
        finding.extracted_dep,
        re.IGNORECASE,
    ))


def _pure_shell_variable_name(dep: str) -> str:
    dep = dep.strip("'\"")
    batch_match = re.fullmatch(r"%(?P<var>[A-Za-z_][A-Za-z0-9_]*)%", dep)
    if batch_match:
        return batch_match.group("var").lower()
    match = re.fullmatch(r"\$\{?(?P<var>[A-Za-z_][A-Za-z0-9_]*)\}?", dep)
    return match.group("var").lower() if match else ""


def _nearest_prior_url_assignment(lines: list[str], var: str) -> str:
    for line in reversed(lines):
        match = re.match(
            r"\s*set\s+(?P<var>[A-Za-z_][A-Za-z0-9_]*)="
            r"['\"]?(?P<url>https?://[^'\"\s]+)['\"]?",
            line,
            re.IGNORECASE,
        )
        if match and match.group("var").lower() == var:
            return _normalize_url_dep(match.group("url"))
        match = re.match(
            r"\s*(?:ENV|ARG)\s+(?P<var>[A-Za-z_][A-Za-z0-9_]*)="
            r"['\"]?(?P<url>https?://[^'\"\s]+)['\"]?",
            line,
            re.IGNORECASE,
        )
        if match and match.group("var").lower() == var:
            return _normalize_url_dep(match.group("url"))
        match = re.match(
            r"\s*(?:export\s+)?(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
            r"['\"]?(?P<url>https?://[^'\"\s]+)['\"]?",
            line,
            re.IGNORECASE,
        )
        if not match:
            match = re.match(
                r"\s*\$(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
                r"['\"]?(?P<url>https?://[^'\"\s]+)['\"]?",
                line,
                re.IGNORECASE,
            )
        if match and match.group("var").lower() == var:
            return _normalize_url_dep(match.group("url"))
    return ""


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


def _is_powershell_metadata_string_download_line(
    target: FileTarget,
    lines: list[str],
    finding: Finding,
) -> bool:
    if (
        target.file_type != "script"
        or target.path.suffix.lower() not in {".ps1", ".psm1", ".psd1"}
        or finding.pattern_id not in {"curl-download", "curl-download-url-first", "wget-download"}
        or not (0 < finding.line_number <= len(lines))
    ):
        return False
    line = lines[finding.line_number - 1]
    return bool(re.match(
        r"""\s*['"](?:Original|Secure|Example|Pattern|Replacement|Description)['"]\s*=\s*['"][^'"]*\b(?:curl|wget)\b""",
        line,
        re.IGNORECASE,
    ))


def _is_jsonc_commented_binary_download_line(
    target: FileTarget,
    lines: list[str],
    line_number: int,
    dep: str,
) -> bool:
    if target.file_type != "devcontainer" or not dep or not (0 < line_number <= len(lines)):
        return False
    line = lines[line_number - 1]
    dep_index = line.find(dep)
    if dep_index == -1 and dep.endswith("\\"):
        dep_index = line.find(dep.rstrip("\\"))
    if dep_index == -1:
        return False
    prefix = line[:dep_index]
    if prefix.strip().startswith("//"):
        return True
    return prefix.rfind("/*") > prefix.rfind("*/")


def _is_non_control_markdown_binary_download_example(
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
    if _is_article_markdown_path(target.rel_path):
        return _is_markdown_code_example_line(lines, finding.line_number, finding.extracted_dep)
    if _is_documentation_markdown_path(target.rel_path):
        return _is_markdown_code_example_line(lines, finding.line_number, finding.extracted_dep)
    if not _is_ordinary_markdown_doc_name(name):
        return False
    return _is_markdown_code_example_line(lines, finding.line_number, finding.extracted_dep)


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
        or normalized == "quick_reference"
        or normalized == "dev_setup"
        or normalized.startswith("readme_")
        or normalized.endswith("_readme")
        or normalized.endswith("_install")
        or normalized.endswith("_installation")
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
        if (dep and dep in span and _BINARY_MARKDOWN_COMMAND_RE.search(span)) or _download_command_in_span(span):
            return True
        start = end + 1


def _download_command_in_span(span: str) -> bool:
    return bool(
        re.search(r"\b(?:curl|wget)\b[^\n`]*https?://[^\s`]+", span, re.IGNORECASE)
        or re.search(r"\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b[^\n`]*https?://[^\s`]+", span, re.IGNORECASE)
        or re.search(r"\b(?:aws\s+s3\s+cp|gsutil\s+cp)\b[^\n`]*(?:s3|gs)://", span, re.IGNORECASE)
    )


def _dedupe_findings_by_file_dependency(findings: list[Finding]) -> list[Finding]:
    deduped: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    direct_python_downloads = {
        (finding.file_path, finding.extracted_dep)
        for finding in findings
        if finding.pattern_id in _PYTHON_DIRECT_DOWNLOAD_PATTERN_IDS
    }
    for finding in findings:
        if (
            finding.pattern_id == "python-download-helper-url"
            and (finding.file_path, finding.extracted_dep) in direct_python_downloads
        ):
            continue
        key = (finding.file_path, finding.pattern_id, finding.extracted_dep)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped


def _normalize_url_dependency_findings(findings: list[Finding]) -> list[Finding]:
    normalized: list[Finding] = []
    for finding in findings:
        dep = _normalize_url_dep(finding.extracted_dep)
        if dep == finding.extracted_dep:
            normalized.append(finding)
            continue
        normalized.append(Finding(
            file_path=finding.file_path,
            line_number=finding.line_number,
            category=finding.category,
            severity=finding.severity,
            pattern_id=finding.pattern_id,
            matched_text=finding.matched_text,
            extracted_dep=dep,
            description=finding.description.replace(finding.extracted_dep, dep),
            scanner_name=finding.scanner_name,
            end_line=finding.end_line,
            analysis_source=finding.analysis_source,
            confidence=finding.confidence,
            enrichment=finding.enrichment,
        ))
    return normalized


def _replace_finding_dep(finding: Finding, dep: str) -> Finding:
    return Finding(
        file_path=finding.file_path,
        line_number=finding.line_number,
        category=finding.category,
        severity=finding.severity,
        pattern_id=finding.pattern_id,
        matched_text=finding.matched_text,
        extracted_dep=dep,
        description=finding.description.replace(finding.extracted_dep, dep),
        scanner_name=finding.scanner_name,
        end_line=finding.end_line,
        analysis_source=finding.analysis_source,
        confidence=finding.confidence,
        enrichment=finding.enrichment,
    )


def _normalize_url_dep(dep: str) -> str:
    if not re.match(r"^https?://", dep, re.IGNORECASE):
        return dep
    return dep.rstrip(" \t\r\n\"'`;,\\")


def _normalize_gh_release_dependency_findings(findings: list[Finding]) -> list[Finding]:
    normalized: list[Finding] = []
    for finding in findings:
        if finding.pattern_id != "gh-release-download":
            normalized.append(finding)
            continue
        dep = finding.extracted_dep.strip("\"'`")
        if dep == finding.extracted_dep:
            normalized.append(finding)
            continue
        normalized.append(Finding(
            file_path=finding.file_path,
            line_number=finding.line_number,
            category=finding.category,
            severity=finding.severity,
            pattern_id=finding.pattern_id,
            matched_text=finding.matched_text,
            extracted_dep=dep,
            description=finding.description.replace(finding.extracted_dep, dep),
            scanner_name=finding.scanner_name,
            end_line=finding.end_line,
            analysis_source=finding.analysis_source,
            confidence=finding.confidence,
            enrichment=finding.enrichment,
        ))
    return normalized


def _scan_powershell_variable_binary_downloads(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type not in set(_ALL_SCRIPTABLE):
        return []

    url_vars = _collect_powershell_url_assignments(lines)
    helper_names = _collect_powershell_download_helper_names(lines)
    helper_return_urls = _collect_powershell_download_helper_return_urls(lines)
    helper_url_vars = _collect_powershell_helper_return_url_assignments(lines, helper_return_urls)
    has_dynamic_download_props = any(_POWERSHELL_DYNAMIC_DOWNLOAD_PROP_RE.search(line) for line in lines)
    has_dynamic_nuget_downloads = any(_POWERSHELL_DYNAMIC_NUGET_URL_VAR_RE.search(line) for line in lines)
    if (
        not url_vars
        and not helper_names
        and not helper_url_vars
        and not has_dynamic_download_props
        and not has_dynamic_nuget_downloads
    ):
        return []

    existing_keys = {
        (finding.line_number, finding.pattern_id, finding.extracted_dep)
        for finding in existing
    }
    added: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        if _is_manual_download_comment_line(target, line) or _looks_like_printed_help(line):
            continue
        for pattern_id, dep in _extract_powershell_variable_downloads(line, url_vars):
            if not _is_binary_artifact_url(dep):
                continue
            key = (line_number, pattern_id, dep)
            if key in existing_keys:
                continue
            added.append(Finding(
                file_path=target.rel_path,
                line_number=line_number,
                category=Category.BINARY_DOWNLOAD,
                severity=Severity.HIGH,
                pattern_id=pattern_id,
                matched_text=line.strip()[:200],
                extracted_dep=dep[:200],
                description=_powershell_download_description(pattern_id, dep[:200]),
                scanner_name=BinaryDownloadScanner.name,
            ))
            existing_keys.add(key)
        for pattern_id, dep in _extract_powershell_multi_variable_downloads(line, helper_url_vars):
            if not _is_binary_artifact_url(dep):
                continue
            key = (line_number, pattern_id, dep)
            if key in existing_keys:
                continue
            added.append(Finding(
                file_path=target.rel_path,
                line_number=line_number,
                category=Category.BINARY_DOWNLOAD,
                severity=Severity.HIGH,
                pattern_id=pattern_id,
                matched_text=line.strip()[:200],
                extracted_dep=dep[:200],
                description=_powershell_download_description(pattern_id, dep[:200]),
                scanner_name=BinaryDownloadScanner.name,
            ))
            existing_keys.add(key)
        for pattern_id, dep in _extract_powershell_dynamic_asset_downloads(line):
            key = (line_number, pattern_id, dep)
            if key in existing_keys:
                continue
            added.append(Finding(
                file_path=target.rel_path,
                line_number=line_number,
                category=Category.BINARY_DOWNLOAD,
                severity=Severity.HIGH,
                pattern_id=pattern_id,
                matched_text=line.strip()[:200],
                extracted_dep=dep[:200],
                description=_powershell_download_description(pattern_id, dep[:200]),
                scanner_name=BinaryDownloadScanner.name,
            ))
            existing_keys.add(key)
        for pattern_id, dep in _extract_powershell_dynamic_nuget_package_downloads(line):
            key = (line_number, pattern_id, dep)
            if key in existing_keys:
                continue
            added.append(Finding(
                file_path=target.rel_path,
                line_number=line_number,
                category=Category.BINARY_DOWNLOAD,
                severity=Severity.MEDIUM,
                pattern_id=pattern_id,
                matched_text=line.strip()[:200],
                extracted_dep=dep[:200],
                description=_powershell_download_description(pattern_id, dep[:200]),
                scanner_name=BinaryDownloadScanner.name,
            ))
            existing_keys.add(key)
        for dep in _extract_powershell_helper_literal_downloads(line, helper_names):
            if not _is_binary_artifact_url(dep):
                continue
            key = (line_number, "powershell-download-helper-url", dep)
            if key in existing_keys:
                continue
            added.append(Finding(
                file_path=target.rel_path,
                line_number=line_number,
                category=Category.BINARY_DOWNLOAD,
                severity=Severity.HIGH,
                pattern_id="powershell-download-helper-url",
                matched_text=line.strip()[:200],
                extracted_dep=dep[:200],
                description=f"PowerShell download helper receives binary artifact URL: {dep[:200]}",
                scanner_name=BinaryDownloadScanner.name,
            ))
            existing_keys.add(key)
    return added


def _scan_powershell_literal_web_downloads(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type not in set(_ALL_SCRIPTABLE):
        return []

    existing_keys = {
        (finding.line_number, finding.pattern_id, finding.extracted_dep)
        for finding in existing
    }
    added: list[Finding] = []
    for line_number, line in _powershell_logical_lines(lines):
        if _is_manual_download_comment_line(target, line) or _looks_like_printed_help(line):
            continue
        for match in _POWERSHELL_LITERAL_WEB_DOWNLOAD_RE.finditer(line):
            for dep in (_normalize_url_dep(url) for url in _extract_literal_urls(match.group("body"))):
                if not _is_binary_artifact_url(dep):
                    continue
                key = (line_number, "powershell-invoke-webrequest", dep)
                if key in existing_keys:
                    continue
                added.append(Finding(
                    file_path=target.rel_path,
                    line_number=line_number,
                    category=Category.BINARY_DOWNLOAD,
                    severity=Severity.HIGH,
                    pattern_id="powershell-invoke-webrequest",
                    matched_text=line.strip()[:200],
                    extracted_dep=dep[:200],
                    description=f"PowerShell download via Invoke-WebRequest: {dep[:200]}",
                    scanner_name=BinaryDownloadScanner.name,
                ))
                existing_keys.add(key)
    return added


def _powershell_logical_lines(lines: list[str]) -> list[tuple[int, str]]:
    logical: list[tuple[int, str]] = []
    start_line = 0
    current = ""
    for line_number, line in enumerate(lines, start=1):
        stripped_right = line.rstrip()
        if current:
            current += " " + stripped_right.strip()
        else:
            start_line = line_number
            current = stripped_right
        if current.rstrip().endswith("`"):
            current = current.rstrip()[:-1].rstrip()
            continue
        logical.append((start_line, current))
        current = ""
        start_line = 0
    if current:
        logical.append((start_line or len(lines), current))
    return logical


def _collect_powershell_url_assignments(lines: list[str]) -> dict[str, str]:
    url_vars: dict[str, str] = {}
    for line in lines:
        if _looks_like_printed_help(line):
            continue
        match = _POWERSHELL_URL_ASSIGN_RE.search(line)
        if not match:
            continue
        dep = _normalize_url_dep(match.group("url"))
        if dep and not is_placeholder_url_dependency(dep):
            url_vars[_powershell_var_key(match.group("var"))] = dep
    return url_vars


def _extract_powershell_variable_downloads(line: str, url_vars: dict[str, str]) -> list[tuple[str, str]]:
    if not url_vars:
        return []
    downloads: list[tuple[str, str]] = []
    for match in _POWERSHELL_WEBCLIENT_DOWNLOADFILE_RE.finditer(line):
        for dep in _resolve_powershell_url_vars(match.group("src"), url_vars):
            downloads.append(("powershell-webclient-download", dep))
    for match in _POWERSHELL_WEB_CMDLET_DOWNLOAD_RE.finditer(line):
        for dep in _resolve_powershell_url_vars(match.group("body"), url_vars):
            downloads.append(("powershell-invoke-webrequest", dep))
    for match in _POWERSHELL_WEB_CMDLET_RE.finditer(line):
        for dep in _resolve_powershell_url_vars(match.group("body"), url_vars):
            downloads.append(("powershell-invoke-webrequest", dep))
    for match in _POWERSHELL_BITS_TRANSFER_RE.finditer(line):
        for dep in _resolve_powershell_url_vars(match.group("body"), url_vars):
            downloads.append(("powershell-bits-transfer", dep))
    return downloads


def _extract_powershell_multi_variable_downloads(
    line: str,
    url_vars: dict[str, set[str]],
) -> list[tuple[str, str]]:
    if not url_vars:
        return []
    downloads: list[tuple[str, str]] = []
    for match in _POWERSHELL_WEBCLIENT_DOWNLOADFILE_RE.finditer(line):
        for dep in _resolve_powershell_multi_url_vars(match.group("src"), url_vars):
            downloads.append(("powershell-webclient-download", dep))
    for match in _POWERSHELL_WEB_CMDLET_DOWNLOAD_RE.finditer(line):
        for dep in _resolve_powershell_multi_url_vars(match.group("body"), url_vars):
            downloads.append(("powershell-invoke-webrequest", dep))
    for match in _POWERSHELL_WEB_CMDLET_RE.finditer(line):
        for dep in _resolve_powershell_multi_url_vars(match.group("body"), url_vars):
            downloads.append(("powershell-invoke-webrequest", dep))
    for match in _POWERSHELL_BITS_TRANSFER_RE.finditer(line):
        for dep in _resolve_powershell_multi_url_vars(match.group("body"), url_vars):
            downloads.append(("powershell-bits-transfer", dep))
    return downloads


def _extract_powershell_dynamic_asset_downloads(line: str) -> list[tuple[str, str]]:
    if not _POWERSHELL_WEB_CMDLET_DOWNLOAD_RE.search(line):
        return []
    if not any(_powershell_binary_dest_hint(match.group("dest")) for match in _POWERSHELL_OUTFILE_ARG_RE.finditer(line)):
        return []

    downloads: list[tuple[str, str]] = []
    for match in _POWERSHELL_DYNAMIC_DOWNLOAD_PROP_RE.finditer(line):
        dep = "$" + _powershell_var_key(match.group("dep"))
        item = ("powershell-dynamic-asset-download", dep)
        if item not in downloads:
            downloads.append(item)
    return downloads


def _extract_powershell_dynamic_nuget_package_downloads(line: str) -> list[tuple[str, str]]:
    if not _POWERSHELL_WEB_CMDLET_DOWNLOAD_RE.search(line):
        return []
    if not any(_powershell_nuget_package_dest_hint(match.group("dest")) for match in _POWERSHELL_OUTFILE_ARG_RE.finditer(line)):
        return []

    downloads: list[tuple[str, str]] = []
    for match in _POWERSHELL_DYNAMIC_NUGET_URL_VAR_RE.finditer(line):
        dep = "$" + _powershell_var_key(match.group(0))
        item = ("powershell-dynamic-nuget-package-download", dep)
        if item not in downloads:
            downloads.append(item)
    return downloads


def _powershell_binary_dest_hint(expr: str) -> bool:
    expr = expr.strip().strip("'\"`")
    if not expr:
        return False
    return bool(
        _BINARY_ARTIFACT_URL_HINT_RE.search("https://example.invalid/" + expr)
        or _PY_BINARY_DEST_HINT_RE.search(expr)
    )


def _powershell_nuget_package_dest_hint(expr: str) -> bool:
    expr = expr.strip().strip("'\"`")
    if not expr:
        return False
    lowered = expr.lower()
    if any(hint in lowered for hint in ("downloadedfile", "nuget", "nupkg", "package")):
        return True
    return _powershell_binary_dest_hint(expr)


def _resolve_powershell_url_vars(text: str, url_vars: dict[str, str]) -> list[str]:
    deps: list[str] = []
    for match in _POWERSHELL_VAR_RE.finditer(text):
        dep = url_vars.get(_powershell_var_key(match.group(0)))
        if dep:
            deps.append(dep)
    return _unique(deps)


def _resolve_powershell_multi_url_vars(
    text: str,
    url_vars: dict[str, set[str]],
) -> list[str]:
    deps: list[str] = []
    for match in _POWERSHELL_VAR_RE.finditer(text):
        deps.extend(sorted(url_vars.get(_powershell_var_key(match.group(0)), set())))
    return _unique(deps)


def _collect_powershell_download_helper_names(lines: list[str]) -> set[str]:
    names: set[str] = set()
    index = 0
    while index < len(lines):
        function = _powershell_function_body_at(lines, index)
        if function is None:
            index += 1
            continue
        name, body, index = function
        body_text = "\n".join(body)
        if _POWERSHELL_DOWNLOAD_HELPER_NAME_RE.search(name) and _POWERSHELL_DOWNLOAD_HELPER_BODY_RE.search(body_text):
            names.add(name.lower())
    return names


def _collect_powershell_download_helper_return_urls(lines: list[str]) -> dict[str, set[str]]:
    helpers: dict[str, set[str]] = {}
    for start_index, _ in enumerate(lines):
        function = _powershell_function_body_at(lines, start_index)
        if function is None:
            continue
        name, body, _ = function
        body_text = "\n".join(body)
        if not _POWERSHELL_DOWNLOAD_HELPER_NAME_RE.search(name) or not re.search(r"\breturn\b", body_text, re.IGNORECASE):
            continue
        urls = {
            dep
            for dep in (_normalize_url_dep(url) for url in _extract_literal_urls(body_text))
            if _is_binary_artifact_url(dep)
        }
        if urls:
            helpers[name.lower()] = urls
    return helpers


def _powershell_function_body_at(lines: list[str], start_index: int) -> tuple[str, list[str], int] | None:
    line = lines[start_index]
    match = _POWERSHELL_FUNCTION_DECL_RE.match(line)
    if not match:
        return None
    name = match.group("name")
    body = [line]
    depth = _powershell_brace_delta(line)
    index = start_index + 1
    seen_open = depth > 0
    while index < len(lines):
        if not seen_open:
            stripped = lines[index].strip()
            if not stripped:
                body.append(lines[index])
                index += 1
                continue
            body.append(lines[index])
            depth += _powershell_brace_delta(lines[index])
            seen_open = depth > 0
            index += 1
            if seen_open:
                continue
            return name, body, index
        if depth <= 0:
            break
        body.append(lines[index])
        depth += _powershell_brace_delta(lines[index])
        index += 1
    return (name, body, index) if seen_open else None


def _collect_powershell_helper_return_url_assignments(
    lines: list[str],
    helper_return_urls: dict[str, set[str]],
) -> dict[str, set[str]]:
    if not helper_return_urls:
        return {}
    url_vars: dict[str, set[str]] = {}
    for line in lines:
        stripped = line.lstrip()
        if not stripped or stripped.lower().startswith("function ") or _looks_like_printed_help(line):
            continue
        match = re.match(
            r"\s*(?P<var>\$[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:&\s*)?(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\b",
            line,
            re.IGNORECASE,
        )
        if not match:
            continue
        urls = helper_return_urls.get(match.group("name").lower())
        if urls:
            url_vars.setdefault(_powershell_var_key(match.group("var")), set()).update(urls)
    return url_vars


def _extract_powershell_helper_literal_downloads(line: str, helper_names: set[str]) -> list[str]:
    if not helper_names:
        return []
    stripped = line.lstrip()
    if stripped.lower().startswith("function "):
        return []
    deps: list[str] = []
    for helper_name in helper_names:
        match = re.match(rf"\s*(?:&\s+)?{re.escape(helper_name)}\b(?P<body>.*)", line, re.IGNORECASE)
        if not match:
            continue
        deps.extend(_extract_literal_urls(match.group("body")))
    return _unique([_normalize_url_dep(dep) for dep in deps])


def _extract_literal_urls(text: str) -> list[str]:
    return re.findall(r"https?://(?!" + _LOCALHOST + r")[^\s'\"`),;]+", text, re.IGNORECASE)


def _powershell_brace_delta(line: str) -> int:
    delta = 0
    quote = ""
    escaped = False
    for ch in line:
        if quote:
            if escaped:
                escaped = False
            elif ch == "`":
                escaped = True
            elif ch == quote:
                quote = ""
            continue
        if ch in ("'", '"'):
            quote = ch
            continue
        if ch == "#":
            break
        if ch == "{":
            delta += 1
        elif ch == "}":
            delta -= 1
    return delta


def _powershell_var_key(var: str) -> str:
    return var.strip().lstrip("$").lower()


def _powershell_download_description(pattern_id: str, dep: str) -> str:
    if pattern_id == "powershell-webclient-download":
        return f"PowerShell WebClient.DownloadFile: {dep}"
    if pattern_id == "powershell-bits-transfer":
        return f"PowerShell Start-BitsTransfer downloads binary artifact URL: {dep}"
    if pattern_id == "powershell-dynamic-asset-download":
        return f"PowerShell downloads dynamic binary artifact URL to binary output: {dep}"
    if pattern_id == "powershell-dynamic-nuget-package-download":
        return f"PowerShell downloads dynamic NuGet package URL to package output: {dep}"
    return f"PowerShell download via Invoke-WebRequest: {dep}"


def _scan_dockerfile_add_remote_binary_downloads(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type != "dockerfile":
        return []

    existing_keys = {
        (finding.line_number, finding.pattern_id, finding.extracted_dep)
        for finding in existing
    }
    added: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        match = _DOCKERFILE_ADD_REMOTE_URL_RE.search(line)
        if not match:
            continue
        dep = _normalize_url_dep(match.group("dep"))
        if not _is_binary_artifact_url(dep):
            continue
        key = (line_number, "dockerfile-add-remote-binary", dep)
        if key in existing_keys:
            continue
        added.append(Finding(
            file_path=target.rel_path,
            line_number=line_number,
            category=Category.BINARY_DOWNLOAD,
            severity=Severity.HIGH,
            pattern_id="dockerfile-add-remote-binary",
            matched_text=line.strip()[:200],
            extracted_dep=dep[:200],
            description=f"Dockerfile ADD downloads remote binary artifact URL: {dep[:200]}",
            scanner_name=BinaryDownloadScanner.name,
        ))
        existing_keys.add(key)
    return added


def _scan_archive_pipe_binary_downloads(
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
    direct_literal_download_deps = {
        _normalize_url_dep(finding.extracted_dep)
        for finding in existing
        if finding.file_path == target.rel_path
        and finding.pattern_id in {"curl-download", "curl-download-url-first", "github-release-download", "wget-download"}
    }
    added: list[Finding] = []
    for line_number, line in _shell_continuation_logical_lines(lines):
        if _is_manual_download_comment_line(target, line) or _looks_like_printed_help(line):
            continue
        for match in _ARCHIVE_PIPE_DOWNLOAD_RE.finditer(line):
            dep = _normalize_url_dep(match.group("dep"))
            if not _is_binary_artifact_url(dep):
                continue
            if dep in direct_literal_download_deps:
                continue
            key = (line_number, "archive-pipe-download", dep)
            if key in existing_keys:
                continue
            added.append(Finding(
                file_path=target.rel_path,
                line_number=line_number,
                category=Category.BINARY_DOWNLOAD,
                severity=Severity.HIGH,
                pattern_id="archive-pipe-download",
                matched_text=line.strip()[:200],
                extracted_dep=dep[:200],
                description=f"Archive downloaded from URL and piped to tar: {dep[:200]}",
                scanner_name=BinaryDownloadScanner.name,
            ))
            existing_keys.add(key)
    return added


def _shell_continuation_logical_lines(lines: list[str]) -> list[tuple[int, str]]:
    logical: list[tuple[int, str]] = []
    start_line = 0
    current = ""
    for line_number, line in enumerate(lines, start=1):
        stripped_right = line.rstrip()
        continued = stripped_right.endswith("\\")
        piece = stripped_right[:-1].rstrip() if continued else stripped_right
        if current:
            current += " " + piece.strip()
        else:
            start_line = line_number
            current = piece
        if continued:
            continue
        logical.append((start_line, current))
        current = ""
        start_line = 0
    if current:
        logical.append((start_line or len(lines), current))
    return logical


def _extract_source_archive_pipe_dep(body: str) -> str:
    for url in _extract_literal_urls(body):
        dep = _normalize_url_dep(url)
        if _is_binary_artifact_url(dep):
            return dep
    for match in _SOURCE_TEMPLATE_EXPR_RE.finditer(body):
        expr = match.group("expr").strip()
        if _source_expr_has_urlish_identifier(expr):
            return "${" + expr + "}"
    var_match = re.search(_URLISH_VAR, body)
    return var_match.group(0) if var_match else ""


def _source_expr_has_urlish_identifier(expr: str) -> bool:
    for identifier in _SOURCE_IDENTIFIER_RE.findall(expr):
        identifier_lower = identifier.lower()
        if "url" in identifier_lower or "uri" in identifier_lower:
            return True
    return False


def _is_test_source_path(rel_path: str) -> bool:
    rel_norm = rel_path.replace("\\", "/")
    rel_lower = rel_norm.lower()
    path = f"/{rel_lower}"
    if any(segment in path for segment in (
        "/test/",
        "/tests/",
        "/testing/",
        "/testdata/",
        "/unittest/",
        "/unittests/",
    )):
        return True
    name = rel_lower.rsplit("/", 1)[-1]
    original_name = rel_norm.rsplit("/", 1)[-1]
    return (
        name.startswith("test_")
        or bool(re.match(r"^(?:test|Test)(?:[-_.A-Z0-9]).*\.(?:[cm]?[jt]sx?|py)$", original_name))
        or name.endswith("_test.py")
        or name.endswith(".test.ts")
        or ".spec." in name
    )


def _scan_python_binary_download_apis(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type != "source_code" or not _is_python_source_path(target.rel_path):
        return []

    url_vars = _collect_python_url_assignments(lines)
    url_maps = _collect_python_url_maps(lines)
    urlish_param_scopes = _collect_python_urlish_param_scopes(lines)
    source_param_scopes = _collect_python_download_source_param_scopes(lines)

    existing_keys = {
        (finding.line_number, finding.pattern_id, finding.extracted_dep)
        for finding in existing
    }
    added: list[Finding] = []
    for line_number, matched_text, pattern_id, source_expr, dest_expr in _iter_python_download_sinks(lines):
        dest_hint = _python_binary_dest_hint(dest_expr)
        deps = _resolve_python_url_expr(source_expr, url_vars, url_maps)
        if not deps and dest_hint:
            placeholder_dep = _python_unresolved_download_placeholder_dep(
                source_expr,
                line_number,
                pattern_id,
                urlish_param_scopes,
                source_param_scopes,
            )
            if placeholder_dep:
                deps = [placeholder_dep]
        if not deps:
            continue
        emitted = False
        for dep in deps:
            dep_is_binary_artifact = _is_binary_artifact_url(dep)
            if not dep_is_binary_artifact and _is_metadata_download_dep(dep):
                continue
            if not (dep_is_binary_artifact or dest_hint):
                continue
            key = (line_number, pattern_id, dep)
            if key in existing_keys:
                emitted = True
                continue
            added.append(Finding(
                file_path=target.rel_path,
                line_number=line_number,
                category=Category.BINARY_DOWNLOAD,
                severity=Severity.HIGH,
                pattern_id=pattern_id,
                matched_text=matched_text[:200],
                extracted_dep=dep[:200],
                description=_python_download_description(pattern_id, dep[:200]),
                scanner_name=BinaryDownloadScanner.name,
            ))
            existing_keys.add(key)
            emitted = True
            if emitted or not dest_hint:
                continue
        placeholder_dep = _python_unresolved_download_placeholder_dep(
            source_expr,
            line_number,
            pattern_id,
            urlish_param_scopes,
            source_param_scopes,
        )
        if not placeholder_dep:
            continue
        key = (line_number, pattern_id, placeholder_dep)
        if key in existing_keys:
            continue
        added.append(Finding(
            file_path=target.rel_path,
            line_number=line_number,
            category=Category.BINARY_DOWNLOAD,
            severity=Severity.HIGH,
            pattern_id=pattern_id,
            matched_text=matched_text[:200],
            extracted_dep=placeholder_dep[:200],
            description=_python_download_description(pattern_id, placeholder_dep[:200]),
            scanner_name=BinaryDownloadScanner.name,
        ))
        existing_keys.add(key)
    return added


def _scan_python_requests_content_downloads(
    target: FileTarget,
    content: str,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type != "source_code" or not _is_python_source_path(target.rel_path):
        return []
    try:
        tree = parse_python_source(content)
    except SyntaxError:
        return _scan_python_requests_content_downloads_line_fallback(target, lines, existing)

    string_values = _collect_python_wget_string_values(tree)
    download_url_helpers = _collect_python_download_url_helper_names(tree, string_values)
    dynamic_url_vars = _collect_python_dynamic_download_url_assignments(tree, string_values, download_url_helpers)
    response_downloads = _collect_python_requests_response_downloads(
        tree,
        content,
        lines,
        dynamic_url_vars,
        download_url_helpers,
    )
    chunk_downloads = _collect_python_requests_chunk_downloads(tree, response_downloads)
    content_download_helpers = _collect_python_requests_content_download_helper_functions(
        tree,
        content,
        lines,
        dynamic_url_vars,
        download_url_helpers,
    )
    if not response_downloads and not dynamic_url_vars and not content_download_helpers:
        return []

    binary_dest_vars = _collect_python_binary_dest_assignments(tree)
    binary_handles = _collect_python_binary_write_handles(tree, binary_dest_vars)
    if not binary_handles and not binary_dest_vars:
        return []

    existing_keys = {
        (finding.line_number, finding.pattern_id, finding.extracted_dep)
        for finding in existing
    }
    added: list[Finding] = []
    for node in ast.walk(tree):
        if not _python_call_writes_response_content_to_binary_sink(node, binary_handles, binary_dest_vars):
            continue
        assert isinstance(node, ast.Call)
        download = _python_requests_content_download_from_write_arg(
            node.args[0],
            response_downloads,
            chunk_downloads,
            dynamic_url_vars,
            download_url_helpers,
            content,
            lines,
        )
        if download is None:
            continue
        dep, line_number, matched_text = download
        key = (line_number, "python-requests-content-download", dep)
        if key in existing_keys:
            continue
        added.append(Finding(
            file_path=target.rel_path,
            line_number=line_number,
            category=Category.BINARY_DOWNLOAD,
            severity=Severity.HIGH,
            pattern_id="python-requests-content-download",
            matched_text=matched_text[:200],
            extracted_dep=dep[:200],
            description=_python_download_description("python-requests-content-download", dep[:200]),
            scanner_name=BinaryDownloadScanner.name,
        ))
        existing_keys.add(key)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        helper_name = _python_call_function_name(node.func)
        if helper_name not in content_download_helpers:
            continue
        for dest_index, dep, _, _ in content_download_helpers[helper_name]:
            if dest_index >= len(node.args):
                continue
            if not _python_open_dest_has_binary_hint(node.args[dest_index], binary_dest_vars):
                continue
            line_number = getattr(node, "lineno", 1)
            source_line = lines[line_number - 1] if 0 < line_number <= len(lines) else dep
            matched_text = (ast.get_source_segment(content, node) or source_line).strip()
            key = (line_number, "python-requests-content-download", dep)
            if key in existing_keys:
                continue
            added.append(Finding(
                file_path=target.rel_path,
                line_number=line_number,
                category=Category.BINARY_DOWNLOAD,
                severity=Severity.HIGH,
                pattern_id="python-requests-content-download",
                matched_text=matched_text[:200],
                extracted_dep=dep[:200],
                description=_python_download_description("python-requests-content-download", dep[:200]),
                scanner_name=BinaryDownloadScanner.name,
            ))
            existing_keys.add(key)
    return added


def _scan_python_requests_content_downloads_line_fallback(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    dynamic_url_vars = _collect_python_dynamic_download_url_assignments_lines(lines)
    binary_dest_vars = _collect_python_binary_dest_assignments_lines(lines)
    if not dynamic_url_vars or not binary_dest_vars:
        return []

    response_downloads: dict[str, tuple[str, int, str]] = {}
    chunk_downloads: dict[str, tuple[str, int, str]] = {}
    binary_handles: set[str] = set()
    for line_number, line in enumerate(lines, start=1):
        response = re.search(
            r"(?P<response>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*requests\.get\s*\(\s*(?P<src>[^,\)]+)",
            line,
        )
        if response:
            dep = _python_line_dynamic_dep(response.group("src"), dynamic_url_vars)
            if dep:
                response_downloads[response.group("response").lower()] = (dep, line_number, line.strip())
        handle = re.search(
            r"\bwith\s+open\s*\(\s*(?P<dest>[^,\)]+)[^\n)]*['\"](?:w|a)?b['\"][^\n)]*\)\s+as\s+(?P<handle>[A-Za-z_][A-Za-z0-9_]*)",
            line,
        )
        if handle and _python_line_dest_has_binary_hint(handle.group("dest"), binary_dest_vars):
            binary_handles.add(handle.group("handle").lower())
        chunk = re.search(
            r"\bfor\s+(?P<chunk>[A-Za-z_][A-Za-z0-9_]*)\s+in\s+"
            r"(?P<response>[A-Za-z_][A-Za-z0-9_]*)\.iter_content\s*\(",
            line,
        )
        if chunk:
            download = response_downloads.get(chunk.group("response").lower())
            if download:
                chunk_downloads[chunk.group("chunk").lower()] = download

    if not binary_handles or not chunk_downloads:
        return []

    existing_keys = {
        (finding.line_number, finding.pattern_id, finding.extracted_dep)
        for finding in existing
    }
    added: list[Finding] = []
    for line in lines:
        write = re.search(
            r"\b(?P<handle>[A-Za-z_][A-Za-z0-9_]*)\.write\s*\(\s*(?P<src>[A-Za-z_][A-Za-z0-9_]*)\s*\)",
            line,
        )
        if not write or write.group("handle").lower() not in binary_handles:
            continue
        download = chunk_downloads.get(write.group("src").lower())
        if not download:
            continue
        dep, line_number, matched_text = download
        key = (line_number, "python-requests-content-download", dep)
        if key in existing_keys:
            continue
        added.append(Finding(
            file_path=target.rel_path,
            line_number=line_number,
            category=Category.BINARY_DOWNLOAD,
            severity=Severity.HIGH,
            pattern_id="python-requests-content-download",
            matched_text=matched_text[:200],
            extracted_dep=dep[:200],
            description=_python_download_description("python-requests-content-download", dep[:200]),
            scanner_name=BinaryDownloadScanner.name,
        ))
        existing_keys.add(key)
    return added


def _scan_python_package_url_installs(
    target: FileTarget,
    content: str,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type != "source_code" or not _is_python_source_path(target.rel_path):
        return []
    try:
        tree = parse_python_source(content)
    except SyntaxError:
        return _scan_python_package_url_installs_line_fallback(target, lines, existing)

    string_values = _collect_python_wget_string_values(tree)
    return _python_package_url_install_findings(target, content, lines, tree, string_values, existing)


def _scan_python_package_url_installs_line_fallback(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    string_values = _collect_python_wget_string_values_line_fallback(lines)
    existing_keys = {
        (finding.line_number, finding.pattern_id, finding.extracted_dep)
        for finding in existing
    }
    added: list[Finding] = []
    for index, line in enumerate(lines):
        if _is_source_comment_line(line) or not _line_may_contain_python_package_url_install(line):
            continue
        span = _collect_python_call_span(lines, index)
        tree = _parse_python_wget_tool_span(span)
        if tree is None:
            continue
        for finding in _python_package_url_install_findings(
            target,
            span,
            span.splitlines(),
            tree,
            string_values,
            [],
            line_offset=index,
        ):
            key = (finding.line_number, finding.pattern_id, finding.extracted_dep)
            if key in existing_keys:
                continue
            added.append(finding)
            existing_keys.add(key)
    return added


def _python_package_url_install_findings(
    target: FileTarget,
    content: str,
    lines: list[str],
    tree: ast.AST,
    string_values: dict[str, str],
    existing: list[Finding],
    *,
    line_offset: int = 0,
) -> list[Finding]:
    existing_keys = {
        (finding.line_number, finding.pattern_id, finding.extracted_dep)
        for finding in existing
    }
    added: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not _is_python_package_url_install_call(node):
            continue
        dep = _python_package_url_install_dep(node, string_values)
        if not dep:
            continue
        has_hint = _python_package_url_install_has_hint(node, string_values)
        if not (_is_binary_artifact_url(dep) or has_hint):
            continue
        line_number = line_offset + getattr(node, "lineno", 1)
        key = (line_number, "python-package-url-install", dep)
        if key in existing_keys:
            continue
        source_line = lines[getattr(node, "lineno", 1) - 1] if 0 < getattr(node, "lineno", 1) <= len(lines) else dep
        matched_text = (ast.get_source_segment(content, node) or source_line).strip()[:200]
        added.append(Finding(
            file_path=target.rel_path,
            line_number=line_number,
            category=Category.BINARY_DOWNLOAD,
            severity=Severity.HIGH,
            pattern_id="python-package-url-install",
            matched_text=matched_text,
            extracted_dep=dep[:200],
            description=f"Python package installer installs artifact from URL: {dep[:200]}",
            scanner_name=BinaryDownloadScanner.name,
        ))
        existing_keys.add(key)
    return added


def _is_python_package_url_install_call(call: ast.Call) -> bool:
    if isinstance(call.func, ast.Attribute):
        return call.func.attr in {"install_package_from_url", "install_packages_from_url"}
    return isinstance(call.func, ast.Name) and call.func.id in {
        "install_package_from_url",
        "install_packages_from_url",
    }


def _python_package_url_install_dep(call: ast.Call, string_values: dict[str, str]) -> str:
    url_expr = (
        _python_call_keyword(call, "url")
        or _python_call_keyword(call, "package_url")
        or _python_call_keyword(call, "source_url")
    )
    if url_expr is None and call.args:
        url_expr = call.args[0]
    if url_expr is None:
        return ""
    dep = _normalize_url_dep(_python_wget_stringish_expr(url_expr, string_values))
    return dep if dep.startswith(("http://", "https://")) else ""


def _python_package_url_install_has_hint(call: ast.Call, string_values: dict[str, str]) -> bool:
    for kw in call.keywords:
        if kw.arg in {"package_name", "filename", "file_name", "name"}:
            if _python_package_artifact_name_hint(_python_wget_stringish_expr(kw.value, string_values)):
                return True
    return False


def _line_may_contain_python_package_url_install(line: str) -> bool:
    return "install_package_from_url" in line or "install_packages_from_url" in line


def _python_package_artifact_name_hint(name: str) -> bool:
    name = name.strip().strip("'\"")
    if not name:
        return False
    return _python_binary_dest_hint(name) or _is_binary_artifact_url(f"https://example.invalid/{name}")


def _scan_python_wget_tool_downloads(
    target: FileTarget,
    content: str,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type != "source_code" or not _is_python_source_path(target.rel_path):
        return []
    try:
        tree = parse_python_source(content)
    except SyntaxError:
        return _scan_python_wget_tool_downloads_line_fallback(target, lines, existing)

    string_values = _collect_python_wget_string_values(tree)
    wget_vars = _collect_python_wget_tool_vars(tree)
    existing_keys = {
        (finding.line_number, finding.pattern_id, finding.extracted_dep)
        for finding in existing
    }
    added: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute) or node.func.attr not in {"get", "run"}:
            continue
        if not _is_python_wget_tool_receiver(node.func.value, wget_vars):
            continue

        deps = _extract_python_wget_tool_call_deps(node, string_values)
        if not deps:
            continue
        has_hint = _python_wget_tool_call_has_binary_hint(node, string_values)
        line_number = getattr(node, "lineno", 1)
        matched_text = (ast.get_source_segment(content, node) or lines[line_number - 1]).strip()[:200]
        for dep in deps:
            dep = _normalize_url_dep(dep)
            if not dep:
                continue
            if not (_is_binary_artifact_url(dep) or has_hint):
                continue
            key = (line_number, "python-wget-tool-download", dep)
            if key in existing_keys:
                continue
            added.append(Finding(
                file_path=target.rel_path,
                line_number=line_number,
                category=Category.BINARY_DOWNLOAD,
                severity=Severity.HIGH,
                pattern_id="python-wget-tool-download",
                matched_text=matched_text,
                extracted_dep=dep[:200],
                description=f"Python Wget tool downloads binary artifact URL: {dep[:200]}",
                scanner_name=BinaryDownloadScanner.name,
            ))
            existing_keys.add(key)
    return added


def _scan_python_wget_tool_downloads_line_fallback(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    string_values = _collect_python_wget_string_values_line_fallback(lines)
    wget_vars = _collect_python_wget_tool_vars_line_fallback(lines)
    existing_keys = {
        (finding.line_number, finding.pattern_id, finding.extracted_dep)
        for finding in existing
    }
    added: list[Finding] = []
    for index, line in enumerate(lines):
        if _is_source_comment_line(line) or not _line_may_contain_python_wget_tool_call(line):
            continue
        span = _collect_python_call_span(lines, index)
        tree = _parse_python_wget_tool_span(span)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Attribute) or node.func.attr not in {"get", "run"}:
                continue
            if not _is_python_wget_tool_receiver(node.func.value, wget_vars):
                continue
            deps = _extract_python_wget_tool_call_deps(node, string_values)
            if not deps:
                continue
            has_hint = _python_wget_tool_call_has_binary_hint(node, string_values)
            line_number = index + getattr(node, "lineno", 1)
            matched_text = span.strip()[:200]
            for dep in deps:
                dep = _normalize_url_dep(dep)
                if not dep:
                    continue
                if not (_is_binary_artifact_url(dep) or has_hint):
                    continue
                key = (line_number, "python-wget-tool-download", dep)
                if key in existing_keys:
                    continue
                added.append(Finding(
                    file_path=target.rel_path,
                    line_number=line_number,
                    category=Category.BINARY_DOWNLOAD,
                    severity=Severity.HIGH,
                    pattern_id="python-wget-tool-download",
                    matched_text=matched_text,
                    extracted_dep=dep[:200],
                    description=f"Python Wget tool downloads binary artifact URL: {dep[:200]}",
                    scanner_name=BinaryDownloadScanner.name,
                ))
                existing_keys.add(key)
    return added


def _collect_python_wget_string_values(tree: ast.AST) -> dict[str, str]:
    values: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            value = _python_wget_stringish_expr(node.value, values)
            if not value:
                continue
            for target in node.targets:
                _store_python_wget_string_value(values, target, value)
        elif isinstance(node, ast.AnnAssign):
            value = _python_wget_stringish_expr(node.value, values) if node.value else ""
            if value:
                _store_python_wget_string_value(values, node.target, value)
    return values


def _collect_python_wget_string_values_line_fallback(lines: list[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    index = 0
    while index < len(lines):
        line = lines[index]
        if _is_source_comment_line(line) or not _line_may_contain_python_assignment(line):
            index += 1
            continue
        span = _collect_python_call_span(lines, index)
        tree = _parse_python_wget_tool_span(span)
        if tree is None:
            index += 1
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                value = _python_wget_stringish_expr(node.value, values)
                if value:
                    for target in node.targets:
                        _store_python_wget_string_value(values, target, value)
            elif isinstance(node, ast.AnnAssign):
                value = _python_wget_stringish_expr(node.value, values) if node.value else ""
                if value:
                    _store_python_wget_string_value(values, node.target, value)
        index += max(1, len(span.splitlines()))
    return values


def _store_python_wget_string_value(values: dict[str, str], target: ast.AST, value: str) -> None:
    if isinstance(target, ast.Name):
        values[target.id.lower()] = value
    elif isinstance(target, ast.Attribute):
        values[target.attr.lower()] = value


def _collect_python_wget_tool_vars(tree: ast.AST) -> set[str]:
    vars_: set[str] = set()
    for node in ast.walk(tree):
        targets: list[ast.AST] = []
        value: ast.AST | None = None
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
            value = node.value
        if value is None or not _is_python_wget_tool_access(value):
            continue
        for target in targets:
            if isinstance(target, ast.Name):
                vars_.add(target.id)
    return vars_


def _collect_python_wget_tool_vars_line_fallback(lines: list[str]) -> set[str]:
    vars_: set[str] = set()
    for line in lines:
        if _is_source_comment_line(line):
            continue
        match = re.search(
            r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=]+)?=\s*"
            r".*?\.tools\s*\[\s*Wget\s*\]",
            line,
        )
        if match:
            vars_.add(match.group("name"))
    return vars_


def _extract_python_wget_tool_call_deps(
    call: ast.Call,
    string_values: dict[str, str],
) -> list[str]:
    if not isinstance(call.func, ast.Attribute):
        return []
    if call.func.attr == "get":
        url_expr = _python_call_keyword(call, "url")
        if url_expr is None and call.args:
            url_expr = call.args[0]
        if url_expr is None:
            return []
        dep = _python_wget_stringish_expr(url_expr, string_values)
        return [dep] if dep.startswith(("http://", "https://")) else []

    command_expr = _python_call_keyword(call, "command")
    if command_expr is None and call.args:
        command_expr = call.args[0]
    if command_expr is None:
        return []
    command = _python_wget_stringish_expr(command_expr, string_values)
    dep = _extract_python_wget_tool_run_url(command)
    return [dep] if dep else []


def _python_wget_tool_call_has_binary_hint(
    call: ast.Call,
    string_values: dict[str, str],
) -> bool:
    for kw in call.keywords:
        if kw.arg == "executable" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
        if kw.arg in {"filename", "file_path", "out", "dest", "destination"}:
            if _python_binary_dest_hint(_python_wget_stringish_expr(kw.value, string_values)):
                return True
    for arg in call.args[1:]:
        if _python_binary_dest_hint(_python_wget_stringish_expr(arg, string_values)):
            return True
    if call.func.attr == "run":
        command_expr = _python_call_keyword(call, "command")
        if command_expr is None and call.args:
            command_expr = call.args[0]
        if command_expr is not None:
            command = _python_wget_stringish_expr(command_expr, string_values)
            if re.search(r"(?:^|\s)(?:-O|--output-document)(?:=|\s+)", command):
                return True
    return False


def _python_call_keyword(call: ast.Call, name: str) -> ast.AST | None:
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _line_may_contain_python_wget_tool_call(line: str) -> bool:
    return bool(re.search(
        r"(?:\b[A-Za-z_][A-Za-z0-9_]*|\btools\s*\[\s*Wget\s*\])\s*\.\s*(?:get|run)\s*\(",
        line,
    ))


def _line_may_contain_python_assignment(line: str) -> bool:
    return bool(re.search(
        r"^\s*(?:self\.)?[A-Za-z_][A-Za-z0-9_]*(?:\s*:\s*[^=]+)?\s*=\s*",
        line,
    ))


def _parse_python_wget_tool_span(span: str) -> ast.AST | None:
    source = span.lstrip()
    try:
        return parse_python_source(source)
    except SyntaxError:
        if source.startswith("return "):
            try:
                return parse_python_source("_wget_result = " + source[len("return "):])
            except SyntaxError:
                return None
    return None


def _is_python_wget_tool_receiver(node: ast.AST, wget_vars: set[str]) -> bool:
    if isinstance(node, ast.Name):
        return node.id in wget_vars
    return _is_python_wget_tool_access(node)


def _is_python_wget_tool_access(node: ast.AST) -> bool:
    if not isinstance(node, ast.Subscript):
        return False
    if _python_subscript_slice_name(node.slice) != "Wget":
        return False
    try:
        value = ast.unparse(node.value)
    except Exception:
        return False
    return value == "tools" or value.endswith(".tools") or ".tools." in value


def _python_subscript_slice_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _python_wget_stringish_expr(node: ast.AST, string_values: dict[str, str]) -> str:
    if isinstance(node, ast.Constant):
        if isinstance(node.value, str):
            return node.value
        return ""
    if isinstance(node, ast.Name):
        return string_values.get(node.id.lower(), "${" + node.id + "}")
    if isinstance(node, ast.Attribute):
        return string_values.get(node.attr.lower(), "${" + _python_expr_label(node) + "}")
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                resolved = _python_wget_stringish_expr(value.value, string_values)
                parts.append(resolved if resolved else "${" + _python_wget_expr_label(value.value) + "}")
            else:
                return ""
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _python_wget_stringish_expr(node.left, string_values)
        right = _python_wget_stringish_expr(node.right, string_values)
        return left + right if left and right else ""
    return ""


def _extract_python_wget_tool_run_url(command: str) -> str:
    match = re.search(r"https?://(?!" + _LOCALHOST + r")", command, re.IGNORECASE)
    if not match:
        return ""
    index = match.start()
    end = index
    placeholder_depth = 0
    while end < len(command):
        if command.startswith("${", end):
            placeholder_depth += 1
            end += 2
            continue
        char = command[end]
        if placeholder_depth:
            if char == "}":
                placeholder_depth -= 1
            end += 1
            continue
        if char in " \t\r\n'\"`,;":
            break
        end += 1
    return _normalize_url_dep(command[index:end])


def _python_wget_expr_label(node: ast.AST) -> str:
    return re.sub(r"\s+", "", _python_expr_label(node))


def _collect_python_url_assignments(lines: list[str]) -> dict[str, list[str]]:
    url_vars: dict[str, list[str]] = {}
    try:
        string_values = _collect_python_wget_string_values(parse_python_source("\n".join(lines)))
    except SyntaxError:
        string_values = {}
    for name, value in string_values.items():
        if value.startswith(("http://", "https://")):
            _add_python_url_var(url_vars, name, value)
    for line in lines:
        stripped = line.strip()
        if _is_source_comment_line(stripped):
            continue
        for match in _PY_URL_LITERAL_ASSIGN_RE.finditer(line):
            _add_python_url_var(url_vars, match.group("var"), match.group("url"))
        if stripped.startswith("def ") or stripped.startswith("async def "):
            for match in _PY_URL_DEFAULT_ARG_RE.finditer(line):
                _add_python_url_var(url_vars, match.group("var"), match.group("url"))

        alias = _PY_URL_ALIAS_ASSIGN_RE.search(line)
        if alias:
            for dep in url_vars.get(alias.group("src").lower(), []):
                _add_python_url_var(url_vars, alias.group("var"), dep)
        fallback = _PY_URL_ENV_FALLBACK_RE.search(line)
        if fallback:
            for dep in url_vars.get(fallback.group("src").lower(), []):
                _add_python_url_var(url_vars, fallback.group("var"), dep)
    return url_vars


def _collect_python_url_maps(lines: list[str]) -> dict[str, list[str]]:
    url_maps: dict[str, list[str]] = {}
    index = 0
    while index < len(lines):
        match = _PY_DICT_ASSIGN_START_RE.match(lines[index])
        if not match:
            index += 1
            continue
        name = match.group("var").lower()
        values: list[str] = []
        index += 1
        while index < len(lines):
            line = lines[index]
            if line.lstrip().startswith("}"):
                break
            entry = _PY_DICT_URL_ENTRY_RE.match(line)
            if entry:
                dep = _normalize_url_dep(entry.group("url"))
                if dep and not is_placeholder_url_dependency(dep) and not _is_local_url(dep):
                    values.append(dep)
            index += 1
        if values:
            url_maps[name] = _unique(values)
        index += 1
    return url_maps


def _collect_python_dynamic_download_url_assignments_lines(lines: list[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in lines:
        if _is_source_comment_line(line):
            continue
        literal = re.search(
            r"(?P<var>(?:self\.)?[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
            r"['\"](?P<url>https?://(?!" + _LOCALHOST + r")[^'\"\s]+)['\"]",
            line,
            re.IGNORECASE,
        )
        if literal:
            dep = _normalize_url_dep(literal.group("url"))
            if _is_binary_artifact_url(dep):
                _add_python_line_dynamic_dep(values, literal.group("var"), dep)
            continue
        alias = re.search(
            r"(?P<dst>(?:self\.)?[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
            r"(?P<src>(?:self\.)?[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?)\s*(?:#.*)?$",
            line,
        )
        if alias:
            dep = _python_line_dynamic_dep(alias.group("src"), values)
            if dep:
                _add_python_line_dynamic_dep(values, alias.group("dst"), dep)
    return values


def _collect_python_binary_dest_assignments_lines(lines: list[str]) -> set[str]:
    vars_: set[str] = set()
    for line in lines:
        if _is_source_comment_line(line):
            continue
        match = re.search(
            r"(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<expr>[^\n#]+)",
            line,
        )
        if not match:
            continue
        if "http://" in match.group("expr") or "https://" in match.group("expr"):
            continue
        if _python_response_content_binary_dest_hint(match.group("expr")):
            vars_.add(match.group("var").lower())
    return vars_


def _add_python_line_dynamic_dep(values: dict[str, str], name: str, dep: str) -> None:
    for key in _python_line_expr_keys(name):
        values[key] = dep


def _python_line_dynamic_dep(expr: str, values: dict[str, str]) -> str:
    expr = expr.strip().strip("'\"")
    literal = re.fullmatch(r"https?://[^'\"\s]+", expr)
    if literal:
        dep = _normalize_url_dep(expr)
        return dep if _is_binary_artifact_url(dep) else ""
    for key in _python_line_expr_keys(expr):
        dep = values.get(key)
        if dep:
            return dep
    return ""


def _python_line_expr_keys(expr: str) -> list[str]:
    expr = expr.strip().strip("'\"").lower()
    keys = [expr] if expr else []
    if "." in expr:
        keys.append(expr.rsplit(".", 1)[-1])
    if expr.startswith("self."):
        keys.append(expr.removeprefix("self."))
    return _unique(keys)


def _python_line_dest_has_binary_hint(expr: str, binary_dest_vars: set[str]) -> bool:
    expr = expr.strip().strip("'\"")
    if expr.lower() in binary_dest_vars:
        return True
    return _python_response_content_binary_dest_hint(expr)


def _add_python_url_var(url_vars: dict[str, list[str]], name: str, dep: str) -> None:
    dep = _normalize_url_dep(dep)
    if not dep or is_placeholder_url_dependency(dep) or _is_local_url(dep):
        return
    key = name.lower()
    values = url_vars.setdefault(key, [])
    if dep not in values:
        values.append(dep)


def _collect_python_dynamic_download_url_assignments(
    tree: ast.AST,
    string_values: dict[str, str],
    download_url_helpers: set[str],
) -> dict[str, str]:
    values: dict[str, str] = {}
    for node in ast.walk(tree):
        targets: list[ast.AST] = []
        value: ast.AST | None = None
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
            value = node.value
        if value is None:
            continue
        dep = _python_wget_stringish_expr(value, {**string_values, **values})
        dep = _normalize_url_dep(dep)
        if not dep.startswith(("http://", "https://")) or is_placeholder_url_dependency(dep) or _is_local_url(dep):
            dep = ""
        if not dep:
            dep = _python_dynamic_download_dep_expr(value, values, download_url_helpers)
        if not dep:
            continue
        for target in targets:
            key = _python_dynamic_assignment_key(target)
            if key:
                values[key] = dep
    return values


def _collect_python_requests_response_downloads(
    tree: ast.AST,
    content: str,
    lines: list[str],
    dynamic_url_vars: dict[str, str],
    download_url_helpers: set[str],
) -> dict[str, tuple[str, int, str]]:
    responses: dict[str, tuple[str, int, str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
            continue
        if not _python_call_is_requests_get(node.value):
            continue
        if not node.value.args:
            continue
        dep = _python_dynamic_download_dep_expr(node.value.args[0], dynamic_url_vars, download_url_helpers)
        if not dep:
            continue
        line_number = getattr(node.value.args[0], "lineno", getattr(node, "lineno", 1))
        source_line = lines[line_number - 1] if 0 < line_number <= len(lines) else dep
        matched_text = (ast.get_source_segment(content, node.value) or source_line).strip()
        for target in node.targets:
            if isinstance(target, ast.Name):
                responses[target.id.lower()] = (dep, line_number, matched_text)
    for node in ast.walk(tree):
        if not isinstance(node, ast.With):
            continue
        for item in node.items:
            if not isinstance(item.context_expr, ast.Call) or not _python_call_is_requests_get(item.context_expr):
                continue
            if not isinstance(item.optional_vars, ast.Name) or not item.context_expr.args:
                continue
            dep = _python_dynamic_download_dep_expr(item.context_expr.args[0], dynamic_url_vars, download_url_helpers)
            if not dep:
                continue
            line_number = getattr(item.context_expr, "lineno", getattr(node, "lineno", 1))
            source_line = lines[line_number - 1] if 0 < line_number <= len(lines) else dep
            matched_text = (ast.get_source_segment(content, item.context_expr) or source_line).strip()
            responses[item.optional_vars.id.lower()] = (dep, line_number, matched_text)
    return responses


def _collect_python_requests_chunk_downloads(
    tree: ast.AST,
    response_downloads: dict[str, tuple[str, int, str]],
) -> dict[str, tuple[str, int, str]]:
    chunks: dict[str, tuple[str, int, str]] = {}
    if not response_downloads:
        return chunks
    for node in ast.walk(tree):
        if not isinstance(node, ast.For) or not isinstance(node.target, ast.Name):
            continue
        if not isinstance(node.iter, ast.Call):
            continue
        func = node.iter.func
        if not isinstance(func, ast.Attribute) or func.attr != "iter_content":
            continue
        if not isinstance(func.value, ast.Name):
            continue
        download = response_downloads.get(func.value.id.lower())
        if download:
            chunks[node.target.id.lower()] = download
    return chunks


def _collect_python_requests_content_download_helper_functions(
    tree: ast.AST,
    content: str,
    lines: list[str],
    dynamic_url_vars: dict[str, str],
    download_url_helpers: set[str],
) -> dict[str, list[tuple[int, str, int, str]]]:
    helpers: dict[str, list[tuple[int, str, int, str]]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        param_indexes = {
            arg.arg.lower(): index
            for index, arg in enumerate(node.args.args)
        }
        if not param_indexes:
            continue
        response_downloads = _collect_python_requests_response_downloads(
            node,
            content,
            lines,
            dynamic_url_vars,
            download_url_helpers,
        )
        if not response_downloads:
            continue
        binary_handles: dict[str, str] = {}
        for child in ast.walk(node):
            if not isinstance(child, ast.With):
                continue
            for item in child.items:
                if not isinstance(item.context_expr, ast.Call) or not _python_call_is_open(item.context_expr):
                    continue
                if not isinstance(item.optional_vars, ast.Name) or not item.context_expr.args:
                    continue
                dest_expr = item.context_expr.args[0]
                if isinstance(dest_expr, ast.Name) and dest_expr.id.lower() in param_indexes:
                    binary_handles[item.optional_vars.id.lower()] = dest_expr.id.lower()
        if not binary_handles:
            continue
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            if not isinstance(child.func, ast.Attribute) or child.func.attr != "write":
                continue
            if not isinstance(child.func.value, ast.Name) or not child.args:
                continue
            param_name = binary_handles.get(child.func.value.id.lower())
            if not param_name:
                continue
            download = _python_requests_content_download_from_write_arg(
                child.args[0],
                response_downloads,
                {},
                dynamic_url_vars,
                download_url_helpers,
                content,
                lines,
            )
            if download is None:
                continue
            dep, line_number, matched_text = download
            item = (param_indexes[param_name], dep, line_number, matched_text)
            helpers.setdefault(node.name, [])
            if item not in helpers[node.name]:
                helpers[node.name].append(item)
    return helpers


def _collect_python_binary_write_handles(tree: ast.AST, binary_dest_vars: set[str]) -> set[str]:
    handles: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.With):
            continue
        for item in node.items:
            if not isinstance(item.context_expr, ast.Call) or not _python_call_is_open(item.context_expr):
                continue
            if not isinstance(item.optional_vars, ast.Name):
                continue
            dest_expr = item.context_expr.args[0] if item.context_expr.args else None
            if dest_expr is None:
                continue
            if not _python_open_dest_has_binary_hint(dest_expr, binary_dest_vars):
                continue
            mode = ""
            if len(item.context_expr.args) > 1:
                mode = _python_literal_string(item.context_expr.args[1])
            mode_expr = _python_call_keyword(item.context_expr, "mode")
            if mode_expr is not None:
                mode = _python_literal_string(mode_expr)
            if mode and "b" not in mode:
                continue
            handles.add(item.optional_vars.id.lower())
    return handles


def _collect_python_binary_dest_assignments(tree: ast.AST) -> set[str]:
    vars_: set[str] = set()
    for node in ast.walk(tree):
        targets: list[ast.AST] = []
        value: ast.AST | None = None
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
            value = node.value
        if value is None:
            continue
        try:
            value_text = ast.unparse(value)
        except Exception:
            value_text = _python_literal_string(value)
        if re.search(r"https?://", value_text, re.IGNORECASE):
            continue
        if not _python_response_content_binary_dest_hint(value_text):
            continue
        for target in targets:
            if isinstance(target, ast.Name):
                vars_.add(target.id.lower())
    return vars_


def _python_open_dest_has_binary_hint(node: ast.AST, binary_dest_vars: set[str]) -> bool:
    if isinstance(node, ast.Name) and node.id.lower() in binary_dest_vars:
        return True
    literal = _python_literal_string(node)
    if literal and _python_response_content_binary_dest_hint(literal):
        return True
    try:
        return _python_response_content_binary_dest_hint(ast.unparse(node))
    except Exception:
        return False


def _collect_python_download_url_helper_names(tree: ast.AST, string_values: dict[str, str]) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for child in ast.walk(node):
            if not isinstance(child, ast.Return) or child.value is None:
                continue
            dep = _python_wget_stringish_expr(child.value, string_values)
            dep = _normalize_url_dep(dep)
            if dep.startswith(("http://", "https://")) and (
                _is_binary_artifact_url(dep)
                or _python_response_content_binary_dest_hint(dep)
            ):
                names.add(node.name)
                break
    return names


def _python_dynamic_download_dep_expr(
    node: ast.AST,
    dynamic_url_vars: dict[str, str],
    download_url_helpers: set[str] | None = None,
) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        dep = _normalize_url_dep(node.value)
        return dep if _is_binary_artifact_url(dep) else ""
    if isinstance(node, ast.Name):
        return dynamic_url_vars.get(node.id.lower(), "")
    if isinstance(node, ast.Call) and _python_call_function_name(node.func) in (download_url_helpers or set()):
        return _python_expr_label(node)
    stringish = _python_wget_stringish_expr(node, dynamic_url_vars)
    if stringish:
        dep = _normalize_url_dep(stringish)
        if dep.startswith(("http://", "https://")) and _is_binary_artifact_url(dep):
            return dep
        if re.search(r"/downloads?/", dep, re.IGNORECASE) or _python_response_content_binary_dest_hint(dep):
            return _python_expr_label(node)
    if isinstance(node, ast.Attribute):
        dep = dynamic_url_vars.get(_python_expr_label(node).lower())
        if dep:
            return dep
        dep = dynamic_url_vars.get(node.attr.lower())
        if dep:
            return dep
        if node.attr.lower() in _PY_DYNAMIC_DOWNLOAD_KEYS:
            return _python_expr_label(node)
    if isinstance(node, ast.Subscript):
        key = _python_subscript_string_key(node.slice)
        if key.lower() in _PY_DYNAMIC_DOWNLOAD_KEYS:
            return _python_expr_label(node)
    return ""


def _python_dynamic_assignment_key(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id.lower()
    if isinstance(node, ast.Attribute):
        return _python_expr_label(node).lower()
    return ""


def _python_response_content_binary_dest_hint(expr: str) -> bool:
    expr = expr.strip().strip("'\"")
    if not expr:
        return False
    if re.search(r"[.](?:json|ya?ml|txt|md)(?:['\")\]}]|$)", expr, re.IGNORECASE):
        return False
    return bool(
        _BINARY_ARTIFACT_URL_HINT_RE.search("https://example.invalid/" + expr)
        or re.search(r"(?:archive|artifact|package|nupkg|vsix|checkpoint|weights?|model|onnx)", expr, re.IGNORECASE)
    )


def _python_call_is_requests_get(call: ast.Call) -> bool:
    return (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == "get"
        and _python_expr_label(call.func.value) == "requests"
    )


def _python_call_is_open(call: ast.Call) -> bool:
    return isinstance(call.func, ast.Name) and call.func.id == "open"


def _python_call_writes_response_content_to_binary_sink(
    node: ast.AST,
    binary_handles: set[str],
    binary_dest_vars: set[str],
) -> bool:
    if not isinstance(node, ast.Call):
        return False
    if not isinstance(node.func, ast.Attribute):
        return False
    if node.func.attr == "write":
        return bool(
            node.args
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id.lower() in binary_handles
        )
    if node.func.attr == "write_bytes":
        if not node.args:
            return False
        if isinstance(node.func.value, ast.Name) and node.func.value.id.lower() in binary_dest_vars:
            return True
        return _python_open_dest_has_binary_hint(node.func.value, binary_dest_vars)
    return False


def _python_requests_content_download_from_write_arg(
    node: ast.AST,
    response_downloads: dict[str, tuple[str, int, str]],
    chunk_downloads: dict[str, tuple[str, int, str]],
    dynamic_url_vars: dict[str, str],
    download_url_helpers: set[str],
    content: str,
    lines: list[str],
) -> tuple[str, int, str] | None:
    if isinstance(node, ast.Name):
        download = chunk_downloads.get(node.id.lower())
        if download:
            return download
    response_name = _python_response_content_name(node)
    if response_name:
        return response_downloads.get(response_name)
    if (
        isinstance(node, ast.Attribute)
        and node.attr == "content"
        and isinstance(node.value, ast.Call)
        and _python_call_is_requests_get(node.value)
        and node.value.args
    ):
        dep = _python_dynamic_download_dep_expr(node.value.args[0], dynamic_url_vars, download_url_helpers)
        if not dep:
            return None
        line_number = getattr(node.value, "lineno", 1)
        source_line = lines[line_number - 1] if 0 < line_number <= len(lines) else dep
        matched_text = (ast.get_source_segment(content, node.value) or source_line).strip()
        return dep, line_number, matched_text
    return None


def _python_response_content_name(node: ast.AST) -> str:
    if (
        isinstance(node, ast.Attribute)
        and node.attr == "content"
        and isinstance(node.value, ast.Name)
    ):
        return node.value.id.lower()
    return ""


def _python_literal_string(node: ast.AST) -> str:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else ""


def _python_subscript_string_key(node: ast.AST) -> str:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else ""


def _iter_python_download_sinks(lines: list[str]) -> list[tuple[int, str, str, str, str]]:
    sinks: list[tuple[int, str, str, str, str]] = []
    start_re = re.compile(
        r"\b(?:urlretrieve|wget\.download|requests\.get|load_state_dict_from_url|super\s*\()",
        re.IGNORECASE,
    )
    for line_number, line in enumerate(lines, start=1):
        if _is_source_comment_line(line) or not start_re.search(line):
            continue
        span = _collect_python_call_span(lines, line_number - 1)
        matched_text = (span.strip() or line.strip())[:200]
        for pattern_id, source_expr, dest_expr in _extract_python_download_sinks(span):
            sinks.append((line_number, matched_text, pattern_id, source_expr, dest_expr))
    return sinks


def _extract_python_download_sinks(line: str) -> list[tuple[str, str, str]]:
    sinks: list[tuple[str, str, str]] = []
    for match in _PY_URLRETRIEVE_RE.finditer(line):
        sinks.append((
            "python-urlretrieve-download",
            match.group("src"),
            match.group("dest") or "",
        ))
    for match in _PY_WGET_DOWNLOAD_RE.finditer(line):
        sinks.append((
            "python-wget-download",
            match.group("src"),
            match.group("dest") or "",
        ))
    for match in _PY_SUPER_INIT_URL_FORWARD_RE.finditer(line):
        sinks.append((
            "python-download-helper-url",
            match.group("src"),
            "",
        ))
    for match in _PY_REQUESTS_STREAM_GET_RE.finditer(line):
        sinks.append((
            "python-requests-stream-download",
            match.group("src"),
            "",
        ))
    for match in _PY_TORCH_LOAD_STATE_DICT_RE.finditer(line):
        sinks.append((
            "python-torch-model-download",
            match.group("src"),
            "",
        ))
    return sinks


def _resolve_python_url_expr(
    expr: str,
    url_vars: dict[str, list[str]],
    url_maps: dict[str, list[str]],
) -> list[str]:
    expr = expr.strip()
    literal = re.fullmatch(r"['\"](?P<url>https?://[^'\"]+)['\"]", expr)
    if literal:
        return [_normalize_url_dep(literal.group("url"))]
    identifier = re.fullmatch(_PY_IDENTIFIER, expr)
    if identifier:
        return url_vars.get(expr.lower(), [])
    subscript = re.fullmatch(r"(?P<var>" + _PY_IDENTIFIER + r")\s*\[[^\]]+\]", expr)
    if subscript:
        return url_maps.get(subscript.group("var").lower(), [])
    return []


def _collect_python_urlish_param_scopes(lines: list[str]) -> dict[int, set[str]]:
    return _collect_python_param_scopes(lines, _PY_URLISH_PARAM_RE)


def _collect_python_download_source_param_scopes(lines: list[str]) -> dict[int, set[str]]:
    return _collect_python_param_scopes(lines, _PY_DOWNLOAD_SOURCE_PARAM_RE)


def _collect_python_param_scopes(
    lines: list[str],
    name_re: re.Pattern[str],
) -> dict[int, set[str]]:
    try:
        tree = parse_python_source("\n".join(lines))
    except SyntaxError:
        return {}

    scopes: dict[int, set[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        args = [
            *getattr(node.args, "posonlyargs", []),
            *node.args.args,
            *node.args.kwonlyargs,
        ]
        if node.args.vararg is not None:
            args.append(node.args.vararg)
        if node.args.kwarg is not None:
            args.append(node.args.kwarg)
        params = {arg.arg.lower() for arg in args if name_re.search(arg.arg)}
        if not params:
            continue
        start_line = getattr(node, "lineno", 1)
        end_line = getattr(node, "end_lineno", start_line)
        for line_number in range(start_line, end_line + 1):
            scopes.setdefault(line_number, set()).update(params)
    return scopes


def _python_expr_is_scoped_urlish_param(
    expr: str,
    line_number: int,
    urlish_param_scopes: dict[int, set[str]],
) -> bool:
    return _python_expr_is_scoped_param(expr, line_number, urlish_param_scopes)


def _python_expr_is_scoped_download_source_param(
    expr: str,
    line_number: int,
    source_param_scopes: dict[int, set[str]],
) -> bool:
    return _python_expr_is_scoped_param(expr, line_number, source_param_scopes)


def _python_expr_is_scoped_param(
    expr: str,
    line_number: int,
    param_scopes: dict[int, set[str]],
) -> bool:
    scoped_params = param_scopes.get(line_number, set())
    if not scoped_params:
        return False
    expr = expr.strip()
    if not re.fullmatch(r"(?:self\.)?" + _PY_IDENTIFIER + r"(?:\." + _PY_IDENTIFIER + r")*", expr):
        return False
    return expr.lower() in scoped_params or expr.rsplit(".", 1)[-1].lower() in scoped_params


def _python_unresolved_urlish_dep(expr: str) -> str:
    expr = expr.strip()
    dotted_identifier = re.fullmatch(r"(?:self\.)?" + _PY_IDENTIFIER + r"(?:\." + _PY_IDENTIFIER + r")*", expr)
    if not dotted_identifier:
        return ""
    last_part = expr.rsplit(".", 1)[-1]
    return "${" + expr + "}" if _PY_URLISH_PARAM_RE.search(last_part) else ""


def _python_unresolved_download_source_dep(expr: str) -> str:
    expr = expr.strip()
    dotted_identifier = re.fullmatch(r"(?:self\.)?" + _PY_IDENTIFIER + r"(?:\." + _PY_IDENTIFIER + r")*", expr)
    if not dotted_identifier:
        return ""
    last_part = expr.rsplit(".", 1)[-1]
    return "${" + expr + "}" if _PY_DOWNLOAD_SOURCE_PARAM_RE.search(last_part) else ""


def _python_unresolved_download_placeholder_dep(
    expr: str,
    line_number: int,
    pattern_id: str,
    urlish_param_scopes: dict[int, set[str]],
    source_param_scopes: dict[int, set[str]],
) -> str:
    placeholder_dep = _python_unresolved_urlish_dep(expr)
    if placeholder_dep and _python_expr_is_scoped_urlish_param(expr, line_number, urlish_param_scopes):
        return placeholder_dep
    if pattern_id != "python-urlretrieve-download":
        return ""
    placeholder_dep = _python_unresolved_download_source_dep(expr)
    if placeholder_dep and _python_expr_is_scoped_download_source_param(expr, line_number, source_param_scopes):
        return placeholder_dep
    return ""


def _python_binary_dest_hint(expr: str) -> bool:
    expr = expr.strip().strip("'\"")
    if not expr:
        return False
    return bool(_PY_BINARY_DEST_HINT_RE.search(expr))


def _is_metadata_download_dep(dep: str) -> bool:
    dep_clean = dep.strip("'\"`")
    return bool(
        _CHECKSUM_TEXT_URL_RE.search(dep_clean)
        or _JSON_METADATA_URL_RE.search(dep_clean)
        or _YAML_METADATA_URL_RE.search(dep_clean)
        or _TEXT_METADATA_URL_RE.search(dep_clean)
        or _CONTAINER_REGISTRY_METADATA_URL_RE.search(dep_clean)
        or _OIDC_OAUTH_METADATA_URL_RE.search(dep_clean)
    )


def _python_download_description(pattern_id: str, dep: str) -> str:
    if pattern_id == "python-download-helper-url":
        return f"Python download helper receives binary artifact URL: {dep}"
    if pattern_id == "python-wget-download":
        return f"Python wget.download fetches binary artifact URL: {dep}"
    if pattern_id == "python-requests-stream-download":
        return f"Python requests streams binary artifact URL: {dep}"
    if pattern_id == "python-requests-content-download":
        return f"Python requests downloads binary response content: {dep}"
    if pattern_id == "python-torch-model-download":
        return f"PyTorch downloads model weights from URL: {dep}"
    return f"Python urlretrieve downloads binary artifact URL: {dep}"


def _is_python_source_path(rel_path: str) -> bool:
    return rel_path.replace("\\", "/").lower().endswith(".py")


def _scan_python_download_helper_call_urls(
    target: FileTarget,
    content: str,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type != "source_code" or not _is_python_source_path(target.rel_path):
        return []
    try:
        tree = parse_python_source(content)
    except SyntaxError:
        return []

    string_values = _collect_python_wget_string_values(tree)
    helper_url_params = _collect_python_download_helper_url_params(tree, string_values)
    if not helper_url_params:
        return []

    existing_keys = {
        (finding.line_number, finding.pattern_id, finding.extracted_dep)
        for finding in existing
    }
    added: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        helper_name = _python_call_function_name(node.func)
        if helper_name not in helper_url_params:
            continue
        for dep in _python_download_helper_call_deps(node, helper_url_params[helper_name], string_values):
            if not _is_binary_artifact_url(dep):
                continue
            line_number = getattr(node, "lineno", 1)
            key = (line_number, "python-download-helper-url", dep)
            if key in existing_keys:
                continue
            source_line = lines[line_number - 1] if 0 < line_number <= len(lines) else dep
            matched_text = (ast.get_source_segment(content, node) or source_line).strip()[:200]
            added.append(Finding(
                file_path=target.rel_path,
                line_number=line_number,
                category=Category.BINARY_DOWNLOAD,
                severity=Severity.HIGH,
                pattern_id="python-download-helper-url",
                matched_text=matched_text,
                extracted_dep=dep[:200],
                description=_python_download_description("python-download-helper-url", dep[:200]),
                scanner_name=BinaryDownloadScanner.name,
            ))
            existing_keys.add(key)
    return added


def _collect_python_download_helper_url_params(
    tree: ast.AST,
    string_values: dict[str, str],
) -> dict[str, dict[str, int]]:
    helpers: dict[str, dict[str, int]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        params = {
            arg.arg.lower(): index
            for index, arg in enumerate(node.args.args)
            if _PY_URLISH_PARAM_RE.search(arg.arg)
        }
        if not params or not _python_function_body_uses_download_param(node, params, string_values):
            continue
        helpers[node.name] = params
    return helpers


def _python_function_body_uses_download_param(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    params: dict[str, int],
    string_values: dict[str, str],
) -> bool:
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        for text in _python_call_stringish_parts(child, string_values):
            if not re.search(r"\b(?:curl|wget)\b", text, re.IGNORECASE):
                continue
            if any("${" + param + "}" in text or re.search(rf"(?<![\w$]){re.escape(param)}(?![\w])", text) for param in params):
                return True
        if _python_call_is_download_sink_with_param(child, params):
            return True
    return False


def _python_call_stringish_parts(call: ast.Call, string_values: dict[str, str]) -> list[str]:
    parts: list[str] = []
    for arg in call.args:
        text = _python_download_helper_stringish_expr(arg, string_values)
        if text:
            parts.append(text)
    return parts


def _python_download_helper_stringish_expr(node: ast.AST, string_values: dict[str, str]) -> str:
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "split"
    ):
        return _python_wget_stringish_expr(node.func.value, string_values)
    return _python_wget_stringish_expr(node, string_values)


def _python_call_is_download_sink_with_param(call: ast.Call, params: dict[str, int]) -> bool:
    func_name = _python_call_function_name(call.func).lower()
    attr = call.func.attr.lower() if isinstance(call.func, ast.Attribute) else ""
    if attr == "download" or func_name in {"urlretrieve"}:
        candidates = [call.args[0]] if call.args else []
    elif attr in {"get", "run"}:
        candidates = [call.args[0]] if call.args else []
    elif func_name in {"get", "fetch", "download", "download_file", "download_binary"}:
        candidates = [call.args[0]] if call.args else []
    else:
        return False
    return any(isinstance(candidate, ast.Name) and candidate.id.lower() in params for candidate in candidates)


def _python_download_helper_call_deps(
    call: ast.Call,
    params: dict[str, int],
    string_values: dict[str, str],
) -> list[str]:
    deps: list[str] = []
    for name, index in params.items():
        expr = _python_call_keyword(call, name)
        if expr is None and index < len(call.args):
            expr = call.args[index]
        if expr is None:
            continue
        dep = _normalize_url_dep(_python_wget_stringish_expr(expr, string_values))
        if dep.startswith(("http://", "https://")) and not is_placeholder_url_dependency(dep):
            deps.append(dep)
    return _unique(deps)


def _python_call_function_name(func: ast.AST) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _scan_python_huggingface_artifact_downloads(
    target: FileTarget,
    content: str,
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type != "source_code" or not _is_python_source_path(target.rel_path):
        return []
    try:
        tree = parse_python_source(content)
    except SyntaxError:
        return _scan_python_huggingface_downloads_line_fallback(target, content.splitlines(), existing)

    string_vars = _collect_python_string_assignments(tree)
    existing_keys = {
        (finding.line_number, finding.pattern_id, finding.extracted_dep)
        for finding in existing
    }
    added: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        pattern_id = _huggingface_download_pattern_id(node.func)
        if not pattern_id:
            continue

        dynamic_hf_artifact_repo = False
        if pattern_id == "huggingface-from-pretrained-download":
            repo = _python_from_pretrained_model_id(node, string_vars)
            if not _is_concrete_huggingface_load_target_id(repo):
                continue
        elif pattern_id == "huggingface-dataset-load":
            repo = _python_call_arg_string(node, "path", 0, string_vars)
            if not _is_concrete_huggingface_load_target_id(repo):
                continue
        elif pattern_id == "huggingface-artifact-download" and _python_call_function_name(node.func) == "load_attn_procs":
            repo = _python_call_arg_string(node, "pretrained_model_name_or_path", 0, string_vars)
            if not _is_concrete_huggingface_repo_id(repo):
                continue
        else:
            repo = _python_call_arg_string(node, "repo_id", 0, string_vars)
            dynamic_hf_artifact_repo = (
                pattern_id == "huggingface-artifact-download"
                and _python_call_function_name(node.func) == "hf_hub_download"
                and _is_dynamic_huggingface_repo_id(repo)
            )
            if not _is_concrete_huggingface_repo_id(repo) and not dynamic_hf_artifact_repo:
                continue

        if not _is_concrete_huggingface_repo_id(repo) and not dynamic_hf_artifact_repo:
            continue

        filename = _python_huggingface_artifact_filename(node, string_vars)
        if pattern_id == "huggingface-artifact-download":
            if not filename or not _is_huggingface_binary_filename(filename):
                continue
            dep = f"huggingface://{repo.strip('/')}/{filename.lstrip('/')}"
        elif pattern_id == "huggingface-dataset-load":
            dep = f"huggingface-dataset://{repo.strip('/')}/*"
        elif pattern_id == "huggingface-from-pretrained-download":
            dep = f"huggingface://{repo.strip('/')}/*"
        else:
            dep = f"huggingface://{repo.strip('/')}/*"

        key = (getattr(node, "lineno", 1), pattern_id, dep)
        if key in existing_keys:
            continue
        added.append(Finding(
            file_path=target.rel_path,
            line_number=getattr(node, "lineno", 1),
            category=Category.BINARY_DOWNLOAD,
            severity=Severity.HIGH,
            pattern_id=pattern_id,
            matched_text=dep[:200],
            extracted_dep=dep[:200],
            description=_huggingface_download_description(pattern_id, dep[:200]),
            scanner_name=BinaryDownloadScanner.name,
        ))
        existing_keys.add(key)
    return added


def _scan_python_huggingface_downloads_line_fallback(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    existing_keys = {
        (finding.line_number, finding.pattern_id, finding.extracted_dep)
        for finding in existing
    }
    added: list[Finding] = []
    in_triple_quoted_string = False
    for index, line in enumerate(lines):
        stripped = line.lstrip()
        triple_quote_count = _python_triple_quote_count(line)
        if in_triple_quoted_string or stripped.startswith(("#", "'''", '"""')):
            if triple_quote_count % 2:
                in_triple_quoted_string = not in_triple_quoted_string
            continue
        if not re.search(r"\b(?:hf_hub_download|snapshot_download|from_pretrained|load_dataset)\s*\(", line):
            if triple_quote_count % 2:
                in_triple_quoted_string = not in_triple_quoted_string
            continue
        span = _collect_python_call_span(lines, index)
        if re.search(r"\bload_dataset\s*\(", line):
            pattern_id = "huggingface-dataset-load"
            repo = _extract_huggingface_call_string_arg(span, "path", 0)
            if not _is_concrete_huggingface_load_target_id(repo):
                continue
        elif re.search(r"\bfrom_pretrained\s*\(", line):
            pattern_id = "huggingface-from-pretrained-download"
            repo = _extract_python_from_pretrained_string_arg(span)
            if not _is_concrete_huggingface_load_target_id(repo):
                continue
        elif re.search(r"\bsnapshot_download\s*\(", span):
            pattern_id = "huggingface-snapshot-download"
            repo = _extract_huggingface_call_string_arg(span, "repo_id", 0)
        else:
            pattern_id = "huggingface-artifact-download"
            repo = _extract_huggingface_call_string_arg(span, "repo_id", 0)
        if not _is_concrete_huggingface_repo_id(repo):
            continue
        if pattern_id == "huggingface-artifact-download":
            filename = _extract_huggingface_call_string_arg(span, "filename", 1)
            if not filename or not _is_huggingface_binary_filename(filename):
                continue
            dep = f"huggingface://{repo.strip('/')}/{filename.lstrip('/')}"
        elif pattern_id == "huggingface-dataset-load":
            dep = f"huggingface-dataset://{repo.strip('/')}/*"
        else:
            dep = f"huggingface://{repo.strip('/')}/*"
        key = (index + 1, pattern_id, dep)
        if key in existing_keys:
            continue
        added.append(Finding(
            file_path=target.rel_path,
            line_number=index + 1,
            category=Category.BINARY_DOWNLOAD,
            severity=Severity.HIGH,
            pattern_id=pattern_id,
            matched_text=span.strip()[:200],
            extracted_dep=dep[:200],
            description=_huggingface_download_description(pattern_id, dep[:200]),
            scanner_name=BinaryDownloadScanner.name,
        ))
        existing_keys.add(key)
        if triple_quote_count % 2:
            in_triple_quoted_string = not in_triple_quoted_string
    return added


def _scan_dockerfile_huggingface_literal_loads(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type != "dockerfile":
        return []
    existing_keys = {
        (finding.line_number, finding.pattern_id, finding.extracted_dep)
        for finding in existing
    }
    added: list[Finding] = []
    for index, line in enumerate(lines):
        if line.lstrip().startswith("#"):
            continue
        if not re.search(r"\b(?:from_pretrained|load_dataset)\s*\(", line):
            continue
        span = _collect_python_call_span(lines, index)
        if re.search(r"\bload_dataset\s*\(", line):
            pattern_id = "huggingface-dataset-load"
            repo = _extract_huggingface_call_string_arg(span, "path", 0)
            if not _is_concrete_huggingface_load_target_id(repo):
                continue
            dep = f"huggingface-dataset://{repo.strip('/')}/*"
        else:
            pattern_id = "huggingface-from-pretrained-download"
            repo = _extract_python_from_pretrained_string_arg(span)
            if not _is_concrete_huggingface_load_target_id(repo):
                continue
            dep = f"huggingface://{repo.strip('/')}/*"
        key = (index + 1, pattern_id, dep)
        if key in existing_keys:
            continue
        added.append(Finding(
            file_path=target.rel_path,
            line_number=index + 1,
            category=Category.BINARY_DOWNLOAD,
            severity=Severity.HIGH,
            pattern_id=pattern_id,
            matched_text=span.strip()[:200],
            extracted_dep=dep[:200],
            description=_huggingface_download_description(pattern_id, dep[:200]),
            scanner_name=BinaryDownloadScanner.name,
        ))
        existing_keys.add(key)
    return added


def _python_triple_quote_count(line: str) -> int:
    return line.count("'''") + line.count('"""')


def _collect_python_call_span(lines: list[str], index: int) -> str:
    parts: list[str] = []
    depth = 0
    for line in lines[index:index + 20]:
        parts.append(line)
        depth += _python_paren_delta(line)
        if parts and depth <= 0:
            break
    return "\n".join(parts)


def _python_paren_delta(line: str) -> int:
    quote = ""
    escaped = False
    delta = 0
    for ch in line:
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
            continue
        if ch in ("'", '"'):
            quote = ch
        elif ch == "#":
            break
        elif ch == "(":
            delta += 1
        elif ch == ")":
            delta -= 1
    return delta


def _extract_huggingface_call_string_arg(span: str, keyword: str, position: int) -> str:
    keyword_match = re.search(
        rf"\b{re.escape(keyword)}\s*=\s*f?['\"](?P<value>[^'\"]+)['\"]",
        span,
    )
    if keyword_match:
        return _normalize_python_fstring_placeholder(keyword_match.group("value"))

    start = span.find("(")
    end = span.rfind(")")
    body = span[start + 1:end if end > start else len(span)] if start != -1 else span
    string_args = re.findall(r"""(?:^|,)\s*f?['"]([^'"]+)['"]""", body)
    if len(string_args) > position:
        return _normalize_python_fstring_placeholder(string_args[position])
    return ""


def _extract_python_from_pretrained_string_arg(span: str) -> str:
    for keyword in ("pretrained_model_name_or_path", "model_name_or_path", "model_name", "model_id", "repo_id"):
        value = _extract_huggingface_call_string_arg(span, keyword, 0)
        if value:
            return value
    return ""


def _normalize_python_fstring_placeholder(value: str) -> str:
    return re.sub(r"\{([^{}]+)\}", r"${\1}", value)


def _collect_python_string_assignments(tree: ast.AST) -> dict[str, str]:
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


def _huggingface_download_pattern_id(func: ast.AST) -> str:
    if isinstance(func, ast.Name):
        if func.id == "hf_hub_download":
            return "huggingface-artifact-download"
        if func.id == "snapshot_download":
            return "huggingface-snapshot-download"
        if func.id == "load_dataset":
            return "huggingface-dataset-load"
    if isinstance(func, ast.Attribute):
        if func.attr == "hf_hub_download":
            return "huggingface-artifact-download"
        if func.attr == "snapshot_download":
            return "huggingface-snapshot-download"
        if func.attr == "from_pretrained":
            return "huggingface-from-pretrained-download"
        if func.attr == "load_attn_procs":
            return "huggingface-artifact-download"
        if func.attr == "load_dataset":
            return "huggingface-dataset-load"
    return ""


def _python_from_pretrained_model_id(
    call: ast.Call,
    string_vars: dict[str, str],
) -> str:
    for keyword in ("pretrained_model_name_or_path", "model_name_or_path", "model_name", "model_id", "repo_id"):
        for kw in call.keywords:
            if kw.arg == keyword:
                return _python_stringish_expr(kw.value, string_vars)
    if call.args:
        return _python_stringish_expr(call.args[0], string_vars)
    return ""


def _python_call_arg_string(
    call: ast.Call,
    keyword: str,
    position: int,
    string_vars: dict[str, str],
) -> str:
    for kw in call.keywords:
        if kw.arg == keyword:
            return _python_stringish_expr(kw.value, string_vars)
    if len(call.args) > position:
        return _python_stringish_expr(call.args[position], string_vars)
    return ""


def _python_huggingface_artifact_filename(call: ast.Call, string_vars: dict[str, str]) -> str:
    for keyword in ("filename", "weight_name"):
        value = _python_call_arg_string(call, keyword, 1, string_vars)
        if value:
            return value
    return ""


def _python_stringish_expr(node: ast.AST, string_vars: dict[str, str]) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return string_vars.get(node.id.lower(), "${" + node.id + "}")
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
        left = _python_stringish_expr(node.left, string_vars)
        right = _python_stringish_expr(node.right, string_vars)
        return left + right if left and right else ""
    return ""


def _python_expr_label(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    try:
        return ast.unparse(node)
    except Exception:
        return "expr"


def _is_huggingface_binary_filename(filename: str) -> bool:
    if is_placeholder_url_dependency(filename):
        return False
    return bool(_BINARY_ARTIFACT_URL_HINT_RE.search("https://huggingface.co/repo/resolve/main/" + filename))


def _is_concrete_huggingface_repo_id(repo: str) -> bool:
    repo = repo.strip("/")
    if not repo or "${" in repo or "<" in repo or ">" in repo:
        return False
    return bool(re.fullmatch(r"[\w.-]+/[\w.-]+", repo))


def _is_dynamic_huggingface_repo_id(repo: str) -> bool:
    repo = repo.strip("/")
    if not repo or "<" in repo or ">" in repo:
        return False
    placeholders = [name.strip().lower() for name in re.findall(r"\$\{([^}]+)\}", repo)]
    if not placeholders:
        return False
    replaced = re.sub(r"\$\{[^}]+\}", "segment", repo)
    if not re.fullmatch(r"[\w./-]+", replaced):
        return False
    repoish_tokens = ("repo", "model", "pretrained", "owner", "org", "namespace")
    if "/" not in repo:
        return len(placeholders) == 1 and any(token in placeholders[0] for token in repoish_tokens)
    split_repo_tokens = repoish_tokens + ("path_parts", "pathparts")
    return any(any(token in name for token in split_repo_tokens) for name in placeholders)


def _is_concrete_huggingface_load_target_id(repo: str) -> bool:
    if not _is_concrete_huggingface_repo_id(repo):
        return False
    repo = repo.strip("/").lower()
    if repo in {"test/repo", "example/repo", "sample/repo", "dummy/repo", "owner/repo"}:
        return False
    owner, _name = repo.split("/", 1)
    return owner not in {
        "asset",
        "assets",
        "cache",
        "checkpoint",
        "checkpoints",
        "data",
        "dataset",
        "datasets",
        "fixture",
        "fixtures",
        "local",
        "model",
        "models",
        "output",
        "outputs",
        "result",
        "results",
        "test",
        "tests",
        "tmp",
    }


def _huggingface_download_description(pattern_id: str, dep: str) -> str:
    if pattern_id == "huggingface-snapshot-download":
        return f"Hugging Face repository snapshot downloaded outside manifest: {dep}"
    if pattern_id == "huggingface-from-pretrained-download":
        return f"Hugging Face model loaded outside manifest: {dep}"
    if pattern_id == "huggingface-dataset-load":
        return f"Hugging Face dataset loaded outside manifest: {dep}"
    return f"Hugging Face artifact downloaded outside manifest: {dep}"


def _scan_javascript_node_http_binary_downloads(
    target: FileTarget,
    content: str,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if (
        target.file_type != "source_code"
        or not _is_javascript_source_path(target.rel_path)
        or _looks_like_minified_javascript(lines)
        or not (
            (_JS_NODE_HTTP_IMPORT_RE.search(content) and _JS_NODE_HTTP_BINARY_SINK_RE.search(content))
            or _JS_HTTP_CLIENT_BINARY_CALL_RE.search(content)
        )
    ):
        return []

    existing_keys = {
        (finding.line_number, finding.pattern_id, finding.extracted_dep)
        for finding in existing
    }
    added: list[Finding] = []
    constants: dict[str, tuple[list[str], int, int]] = {}
    object_string_props: dict[str, tuple[dict[str, list[str]], int]] = {}
    object_aliases: dict[str, tuple[str, int]] = {}
    brace_depth = 0
    for line_number, line in enumerate(lines, start=1):
        constants = {
            name: value
            for name, value in constants.items()
            if brace_depth >= value[2]
        }
        object_string_props = {
            name: value
            for name, value in object_string_props.items()
            if brace_depth >= value[1]
        }
        object_aliases = {
            name: value
            for name, value in object_aliases.items()
            if brace_depth >= value[1]
        }
        if _is_source_comment_line(line):
            brace_depth = max(0, brace_depth + _js_brace_delta(line))
            continue

        object_props = _collect_js_object_string_props(lines, line_number - 1)
        if object_props:
            object_string_props[object_props[0]] = (object_props[1], brace_depth)

        object_alias = _JS_OBJECT_INDEX_ALIAS_RE.search(line)
        if object_alias:
            object_aliases[object_alias.group("alias")] = (
                object_alias.group("object"),
                brace_depth,
            )

        match = _JS_URL_CONST_ASSIGN_RE.search(line)
        if match:
            _add_js_url_constant(
                constants,
                match.group("name"),
                match.group("expr"),
                line_number,
                brace_depth,
                object_string_props,
                object_aliases,
            )
        else:
            match = _JS_URL_CONST_START_RE.search(line.strip())
            if match:
                expr = _collect_multiline_js_assignment_expr(lines, line_number - 1)
                _add_js_url_constant(
                    constants,
                    match.group("name"),
                    expr,
                    line_number,
                    brace_depth,
                    object_string_props,
                    object_aliases,
                )

        deps = _extract_node_http_literal_binary_urls(line)
        deps.extend(_extract_js_http_client_literal_binary_urls(line))
        if _JS_NODE_HTTP_CALL_RE.search(line) or _JS_HTTP_CLIENT_BINARY_CALL_RE.search(line):
            for name, (constant_deps, _, _) in constants.items():
                if not _line_references_js_identifier(line, name):
                    continue
                if _line_shadows_js_identifier(line, name):
                    continue
                deps.extend(constant_deps)

        for dep in _unique(deps):
            if not _is_binary_artifact_url(dep):
                continue
            key = (line_number, "node-http-binary-download", dep)
            if key in existing_keys:
                continue
            added.append(Finding(
                file_path=target.rel_path,
                line_number=line_number,
                category=Category.BINARY_DOWNLOAD,
                severity=Severity.HIGH,
                pattern_id="node-http-binary-download",
                matched_text=line.strip()[:200],
                extracted_dep=dep[:200],
                description=f"Node http/https downloads binary artifact URL: {dep[:200]}",
                scanner_name=BinaryDownloadScanner.name,
            ))
            existing_keys.add(key)
        for dep in _extract_js_download_helper_dynamic_deps(line, constants):
            key = (line_number, "node-http-dynamic-download", dep)
            if key in existing_keys:
                continue
            added.append(Finding(
                file_path=target.rel_path,
                line_number=line_number,
                category=Category.BINARY_DOWNLOAD,
                severity=Severity.HIGH,
                pattern_id="node-http-dynamic-download",
                matched_text=line.strip()[:200],
                extracted_dep=dep[:200],
                description=f"Node download helper fetches binary artifact URL: {dep[:200]}",
                scanner_name=BinaryDownloadScanner.name,
            ))
            existing_keys.add(key)
        brace_depth = max(0, brace_depth + _js_brace_delta(line))
    return added


def _extract_node_http_literal_binary_urls(line: str) -> list[str]:
    return [match.group("dep") for match in _JS_NODE_HTTP_LITERAL_URL_RE.finditer(line)]


def _extract_js_http_client_literal_binary_urls(line: str) -> list[str]:
    return [match.group("dep") for match in _JS_HTTP_CLIENT_LITERAL_BINARY_URL_RE.finditer(line)]


def _extract_js_download_helper_dynamic_deps(
    line: str,
    constants: dict[str, tuple[list[str], int, int]],
) -> list[str]:
    deps: list[str] = []
    for match in _JS_DOWNLOAD_HELPER_CALL_RE.finditer(line):
        src = match.group("src").strip()
        dest = (match.group("dest") or "").strip()
        if not _js_urlish_identifier(src) or not _js_binary_dest_hint(dest):
            continue
        constant_deps = constants.get(src, ([], 0, 0))[0]
        if constant_deps:
            deps.extend(constant_deps)
        else:
            deps.append("${" + src + "}")
    return _unique(deps)


def _js_urlish_identifier(expr: str) -> bool:
    expr = expr.strip()
    return bool(re.fullmatch(r"[A-Za-z_$][\w$]*", expr) and re.search(r"(?:url|uri)", expr, re.IGNORECASE))


def _js_binary_dest_hint(expr: str) -> bool:
    expr = expr.strip().strip("'\"`")
    if not expr:
        return False
    return bool(
        _PY_BINARY_DEST_HINT_RE.search(expr)
        or _BINARY_ARTIFACT_URL_HINT_RE.search("https://example.invalid/" + expr)
    )


def _add_js_url_constant(
    constants: dict[str, tuple[list[str], int, int]],
    name: str,
    expr: str,
    line_number: int,
    brace_depth: int,
    object_string_props: dict[str, tuple[dict[str, list[str]], int]] | None = None,
    object_aliases: dict[str, tuple[str, int]] | None = None,
) -> None:
    deps = _extract_js_url_constant_deps(
        expr,
        object_string_props=object_string_props or {},
        object_aliases=object_aliases or {},
    )
    deps = [dep for dep in deps if dep and not _is_local_url(dep)]
    if deps:
        constants[name] = (_unique(deps), line_number, brace_depth)


def _collect_multiline_js_assignment_expr(lines: list[str], index: int) -> str:
    parts: list[str] = []
    for next_line in lines[index + 1:index + 5]:
        stripped = next_line.strip()
        if not stripped or _is_source_comment_line(stripped):
            continue
        parts.append(stripped.rstrip(";"))
        if stripped.endswith(";"):
            break
    return " ".join(parts)


def _extract_js_url_constant_deps(
    expr: str,
    *,
    object_string_props: dict[str, tuple[dict[str, list[str]], int]] | None = None,
    object_aliases: dict[str, tuple[str, int]] | None = None,
) -> list[str]:
    dep = _extract_js_url_constant_dep(expr)
    if not dep:
        return []
    return _expand_js_object_property_template_deps(
        dep,
        object_string_props=object_string_props or {},
        object_aliases=object_aliases or {},
    )


def _extract_js_url_constant_dep(expr: str) -> str:
    expr = expr.strip().rstrip(";")
    simple = re.match(r"['\"`](?P<dep>https?://[^'\"`\s]+)['\"`]$", expr)
    if simple:
        return simple.group("dep")

    parts = [part.strip() for part in expr.split("+")]
    if not parts:
        return ""
    dep_parts: list[str] = []
    for part in parts:
        literal = re.fullmatch(r"['\"`](?P<value>[^'\"`]*)['\"`]", part)
        if literal:
            dep_parts.append(literal.group("value"))
            continue
        identifier = re.fullmatch(r"[A-Za-z_$][\w$]*", part)
        if identifier:
            dep_parts.append("${" + part + "}")
            continue
        return ""
    dep = "".join(dep_parts)
    return dep if dep.startswith(("http://", "https://")) else ""


def _collect_js_object_string_props(
    lines: list[str],
    start_index: int,
) -> tuple[str, dict[str, list[str]]] | None:
    start = _JS_OBJECT_CONST_START_RE.match(lines[start_index])
    if not start:
        return None

    props: dict[str, list[str]] = {}
    depth = _js_brace_delta(lines[start_index])
    index = start_index + 1
    while index < len(lines) and depth > 0:
        line = lines[index]
        if not _is_source_comment_line(line):
            for match in _JS_OBJECT_STRING_PROP_RE.finditer(line):
                values = props.setdefault(match.group("prop"), [])
                value = match.group("value")
                if value not in values:
                    values.append(value)
        depth += _js_brace_delta(line)
        index += 1

    return (start.group("name"), props) if props else None


def _expand_js_object_property_template_deps(
    dep: str,
    *,
    object_string_props: dict[str, tuple[dict[str, list[str]], int]],
    object_aliases: dict[str, tuple[str, int]],
) -> list[str]:
    deps = [dep]
    for match in list(_JS_TEMPLATE_OBJECT_PROP_RE.finditer(dep)):
        alias = match.group("object")
        prop = match.group("prop")
        object_name = object_aliases.get(alias, ("", 0))[0]
        values = object_string_props.get(object_name, ({}, 0))[0].get(prop, [])
        if not values:
            continue

        placeholder = match.group(0)
        expanded: list[str] = []
        for current_dep in deps:
            for value in values:
                expanded.append(current_dep.replace(placeholder, value))
                if len(expanded) >= _MAX_JS_TEMPLATE_EXPANSIONS:
                    break
            if len(expanded) >= _MAX_JS_TEMPLATE_EXPANSIONS:
                break
        deps = expanded

    return deps


def _is_binary_artifact_url(dep: str) -> bool:
    dep_clean = dep.strip("'\"`")
    if not re.match(r"^https?://", dep_clean, re.IGNORECASE):
        return False
    if is_placeholder_url_dependency(dep_clean):
        return False
    if _is_local_url(dep_clean):
        return False
    if (
        _CHECKSUM_TEXT_URL_RE.search(dep_clean)
        or _JSON_METADATA_URL_RE.search(dep_clean)
        or _YAML_METADATA_URL_RE.search(dep_clean)
        or _TEXT_METADATA_URL_RE.search(dep_clean)
        or _CONTAINER_REGISTRY_METADATA_URL_RE.search(dep_clean)
        or _OIDC_OAUTH_METADATA_URL_RE.search(dep_clean)
    ):
        return False
    return bool(_BINARY_ARTIFACT_URL_HINT_RE.search(dep_clean))


def _line_references_js_identifier(line: str, name: str) -> bool:
    return bool(re.search(rf"(?:\b{re.escape(name)}\b|\$\{{\s*{re.escape(name)}\s*\}})", line))


def _line_shadows_js_identifier(line: str, name: str) -> bool:
    escaped = re.escape(name)
    return bool(
        re.search(rf"\(\s*{escaped}\s*\)\s*=>", line)
        or re.search(rf"\bfunction\s+[A-Za-z_$][\w$]*\s*\([^)]*\b{escaped}\b", line)
    )


def _is_javascript_source_path(rel_path: str) -> bool:
    return rel_path.replace("\\", "/").lower().endswith(
        (".js", ".mjs", ".cjs", ".ts", ".mts", ".jsx", ".tsx")
    )


def _looks_like_minified_javascript(lines: list[str]) -> bool:
    return any(len(line) > 1000 for line in lines[:20])


def _is_source_comment_line(line: str) -> bool:
    stripped = line.strip()
    return (
        stripped.startswith("//")
        or stripped.startswith("#")
        or stripped.startswith("*")
        or stripped.startswith("/*")
        or stripped.startswith("*/")
    )


def _is_local_url(url: str) -> bool:
    return bool(re.match(rf"https?://(?:{_LOCALHOST})(?:[:/]|$)", url, re.IGNORECASE))


def _js_brace_delta(line: str) -> int:
    delta = 0
    quote = ""
    escaped = False
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
            i += 1
            continue
        if ch in ("'", '"', "`"):
            quote = ch
            i += 1
            continue
        if ch == "/" and i + 1 < len(line) and line[i + 1] == "/":
            break
        if ch == "{":
            delta += 1
        elif ch == "}":
            delta -= 1
        i += 1
    return delta


def _scan_nuget_package_downloads(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type not in set(_ALL_SCRIPTABLE):
        return []

    url_vars: dict[str, str] = {}
    for line in lines:
        match = re.search(
            r"(?P<var>\$[A-Za-z_][A-Za-z0-9_]*)\s*=\s*['\"]"
            r"(?P<url>https?://(?:www\.)?nuget\.org/api/v2/package/[^'\"]+)",
            line,
            re.IGNORECASE,
        )
        if match:
            url_vars[match.group("var").lower()] = match.group("url")

    if not url_vars:
        return []

    existing_keys = {
        (finding.line_number, finding.pattern_id, finding.extracted_dep)
        for finding in existing
    }
    added: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        if not re.search(r"\b(?:curl|Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\b", line, re.IGNORECASE):
            continue
        for var, url in url_vars.items():
            if not re.search(rf"(?<![\w.-]){re.escape(var)}(?![\w.-])", line, re.IGNORECASE):
                continue
            key = (line_number, "nuget-package-download", url)
            if key in existing_keys:
                continue
            added.append(Finding(
                file_path=target.rel_path,
                line_number=line_number,
                category=Category.BINARY_DOWNLOAD,
                severity=Severity.MEDIUM,
                pattern_id="nuget-package-download",
                matched_text=line.strip()[:200],
                extracted_dep=url[:200],
                description=f"NuGet package downloaded directly outside project manifest: {url[:200]}",
                scanner_name=BinaryDownloadScanner.name,
            ))
            existing_keys.add(key)
    return added


def _scan_playwright_browser_installs(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type not in set(_ALL_SCRIPTABLE + ["package_config"]):
        return []
    existing_keys = {
        (finding.line_number, finding.pattern_id, finding.extracted_dep)
        for finding in existing
    }
    added: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        if _is_manual_download_comment_line(target, line) or _looks_like_printed_help(line):
            continue
        for dep in _extract_playwright_browser_installs(line):
            key = (line_number, "playwright-browser-install", dep)
            if key in existing_keys:
                continue
            added.append(Finding(
                file_path=target.rel_path,
                line_number=line_number,
                category=Category.BINARY_DOWNLOAD,
                severity=Severity.HIGH,
                pattern_id="playwright-browser-install",
                matched_text=line.strip()[:200],
                extracted_dep=dep,
                description=f"Playwright downloads browser binary outside manifest: {dep}",
                scanner_name=BinaryDownloadScanner.name,
            ))
            existing_keys.add(key)
    return added


def _scan_puppeteer_browser_installs(
    target: FileTarget,
    lines: list[str],
    existing: list[Finding],
) -> list[Finding]:
    if target.file_type not in set(_ALL_SCRIPTABLE + ["package_config"]):
        return []
    existing_keys = {
        (finding.line_number, finding.pattern_id, finding.extracted_dep)
        for finding in existing
    }
    added: list[Finding] = []
    for line_number, line in enumerate(lines, start=1):
        if _is_manual_download_comment_line(target, line) or _looks_like_printed_help(line):
            continue
        for dep in _extract_puppeteer_browser_installs(line):
            key = (line_number, "puppeteer-browser-install", dep)
            if key in existing_keys:
                continue
            added.append(Finding(
                file_path=target.rel_path,
                line_number=line_number,
                category=Category.BINARY_DOWNLOAD,
                severity=Severity.HIGH,
                pattern_id="puppeteer-browser-install",
                matched_text=line.strip()[:200],
                extracted_dep=dep,
                description=f"Puppeteer downloads browser binary outside manifest: {dep}",
                scanner_name=BinaryDownloadScanner.name,
            ))
            existing_keys.add(key)
    return added


_PLAYWRIGHT_INSTALL_COMMAND_RE = re.compile(
    r"\b(?:"
    r"(?:npx\s+)?playwright(?:-core)?"
    r"|python\s+-m\s+playwright"
    r"|(?:npm|pnpm|yarn)\s+exec(?:\s+--no)?(?:\s+--)?\s+playwright(?:-core)?"
    r")\s+install\b(?!-)",
    re.IGNORECASE,
)
_PLAYWRIGHT_BROWSERS = frozenset({
    "chromium",
    "chrome",
    "chrome-beta",
    "msedge",
    "msedge-beta",
    "msedge-dev",
    "firefox",
    "webkit",
    "ffmpeg",
})
_PUPPETEER_BROWSER_INSTALL_COMMAND_RE = re.compile(
    r"(?<![$\w.-])(?:"
    r"(?:npx\s+)?puppeteer(?:-core)?\s+browsers"
    r"|(?:pnpm|yarn)\s+puppeteer(?:-core)?\s+browsers"
    r"|(?:npm|pnpm|yarn)\s+exec(?:\s+--no)?(?:\s+--)?\s+puppeteer(?:-core)?\s+browsers"
    r"|(?:npx\s+)?@puppeteer/browsers"
    r"|(?:npm|pnpm|yarn)\s+exec(?:\s+--no)?(?:\s+--)?\s+@puppeteer/browsers"
    r")\s+install\b(?!-)",
    re.IGNORECASE,
)
_PUPPETEER_BROWSERS = frozenset({
    "chrome",
    "chrome-headless-shell",
    "chromium",
    "chromedriver",
    "firefox",
})


def _extract_playwright_browser_installs(line: str) -> list[str]:
    deps: list[str] = []
    for match in _PLAYWRIGHT_INSTALL_COMMAND_RE.finditer(line):
        command = match.group(0)
        if command != command.lower() and command.lower().startswith("playwright"):
            continue
        body = re.split(r"(?:&&|\|\||[;|])", line[match.end():], maxsplit=1)[0]
        if "`" in body:
            body = body.split("`", 1)[0]
        tokens = _simple_shell_tokens(body)
        install_deps: list[str] = []
        unknown_operands = False
        for token in tokens:
            dep = token.strip().strip(",").strip("\"'")
            dep = dep.rstrip("\\")
            dep = dep.rstrip("),")
            if not dep.strip("{}[]"):
                continue
            if not dep or dep == "--" or dep.startswith("-"):
                continue
            dep = dep.lower()
            if dep in _PLAYWRIGHT_BROWSERS:
                install_deps.append(dep)
            else:
                unknown_operands = True
        if unknown_operands and not install_deps:
            continue
        deps.extend(install_deps or ["playwright-browsers"])
    return _unique(deps)


def _extract_puppeteer_browser_installs(line: str) -> list[str]:
    deps: list[str] = []
    for match in _PUPPETEER_BROWSER_INSTALL_COMMAND_RE.finditer(line):
        command = match.group(0)
        if command != command.lower() and command.lower().startswith("puppeteer"):
            continue
        body = re.split(r"(?:&&|\|\||[;|])", line[match.end():], maxsplit=1)[0]
        if "`" in body:
            body = body.split("`", 1)[0]
        install_deps: list[str] = []
        unknown_operands = False
        for token in _simple_shell_tokens(body):
            dep = token.strip().strip(",").strip("\"'")
            dep = dep.rstrip("\\")
            dep = dep.rstrip("),")
            if not dep.strip("{}[]"):
                continue
            if not dep or dep == "--" or dep.startswith("-"):
                continue
            dep = dep.lower()
            if _puppeteer_browser_base(dep) in _PUPPETEER_BROWSERS:
                install_deps.append(dep)
            else:
                unknown_operands = True
        if unknown_operands and not install_deps:
            continue
        deps.extend(install_deps)
    return _unique(deps)


def _puppeteer_browser_base(dep: str) -> str:
    return dep.split("@", 1)[0]


def _simple_shell_tokens(text: str) -> list[str]:
    return [t.strip("'\"") for t in re.findall(r'''(?:"[^"]*"|'[^']*'|\S+)''', text) if t.strip("'\"")]


def _is_manual_download_comment_line(target: FileTarget, line: str) -> bool:
    if target.file_type == "script" and re.match(r"(?i)\s*(?:rem(?:\s|$)|::)", line):
        return True
    if target.file_type in {"ci", "script", "build", "dockerfile", "github_action"}:
        stripped = line.lstrip()
        return stripped.startswith("#") and not stripped.startswith("#!")
    return False


def _looks_like_printed_help(line: str) -> bool:
    return bool(re.match(
        r"\s*@?(?:echo|printf|print|warn|fail|pass|log(?:[_-]?\w+)?|info|debug|error|"
        r"Write-[A-Za-z][A-Za-z0-9]*|throw)\b",
        line,
        re.IGNORECASE,
    ))


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out
