"""
package.json scripts scanner.

`package.json` "scripts" entries run on `npm install` (postinstall),
on demand (`npm run x`), or on hook events (prepare, prepublish).
Risky patterns:
- postinstall/preinstall/prepare invoking remote downloads (curl|bash, wget|sh)
- postinstall calling `npx <pkg>@latest`
- scripts that pipe to bash from a remote URL

The unmanaged_packages scanner already catches `npx`/`bunx`/etc when used
in scripts files, but doesn't have eyes on package.json itself unless the
script value contains the pattern. This scanner narrows in on the
*lifecycle hook* context, where execution is implicit.
"""
from __future__ import annotations

import re

from github_inventory.models import Category, Severity
from github_inventory.scanners.base import BaseScanner, PatternRule


class PackageScriptsScanner(BaseScanner):
    name = "package-scripts"

    def register_rules(self) -> None:
        # Lifecycle hooks (postinstall, preinstall, prepare, prepublish, etc.)
        # whose value invokes curl/wget piped to a shell. This is the
        # canonical "scripts can run anything on install" attack vector.
        self.add_rule(PatternRule(
            pattern_id="package-script-postinstall-curl-pipe",
            regex=re.compile(
                r'"(?P<hook>postinstall|preinstall|prepare|prepublish|prepublishOnly|install)"'
                r'\s*:\s*"[^"]*?(?:curl|wget)[^"]*?\|[^"]*?(?:bash|sh|zsh)\b[^"]*"',
                re.IGNORECASE,
            ),
            severity=Severity.CRITICAL,
            description_template="package.json lifecycle script pipes remote script to shell",
            category=Category.PACKAGE_SCRIPT,
            file_types=["package_config"],
            extract_group="hook",
        ))

        # Lifecycle hooks invoking npx/bunx with @latest/@alpha — runs at
        # `npm install` time, no version pin, every install pulls latest.
        self.add_rule(PatternRule(
            pattern_id="package-script-lifecycle-npx-mutable",
            regex=re.compile(
                r'"(?P<hook>postinstall|preinstall|prepare|prepublish|install)"'
                r'\s*:\s*"[^"]*?(?:npx|bunx|pnpm\s+dlx)\s+(?:--?\w+\s+)*'
                r'(?:@[\w-]+/)?[\w][\w.-]*'
                r'@(?:latest|alpha|beta|next|canary|nightly|edge)\b',
                re.IGNORECASE,
            ),
            severity=Severity.CRITICAL,
            description_template="package.json lifecycle script invokes npx with mutable @-tag",
            category=Category.PACKAGE_SCRIPT,
            file_types=["package_config"],
            extract_group="hook",
        ))

        # Any lifecycle hook with a curl/wget invocation (download, even if
        # not piped to bash — could be writing an installer to disk).
        self.add_rule(PatternRule(
            pattern_id="package-script-lifecycle-download",
            regex=re.compile(
                r'"(?P<hook>postinstall|preinstall|prepare|prepublish|install)"'
                r'\s*:\s*"[^"]*?(?:curl|wget|fetch)\s+[^"]*?https?://[^"]+',
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="package.json lifecycle script downloads remote content",
            category=Category.PACKAGE_SCRIPT,
            file_types=["package_config"],
            extract_group="hook",
        ))

        # Any lifecycle hook that runs `node-gyp rebuild` from a non-default
        # location, or `prebuild-install` with a custom `--download` URL.
        self.add_rule(PatternRule(
            pattern_id="package-script-prebuild-install-url",
            regex=re.compile(
                r'"(?:postinstall|install)"\s*:\s*"[^"]*?'
                r'prebuild-install[^"]*?--download[\s=]+(?P<dep>https?://[^"\s]+)',
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            description_template="prebuild-install fetches binary from custom URL: {dep}",
            category=Category.PACKAGE_SCRIPT,
            file_types=["package_config"],
        ))
