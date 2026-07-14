# github-inventory

> Repository-level phantom dependency scanner — **SupplyDrift Vector 1**

Traditional supply chain security tools (Snyk, Dependabot, Trivy) only analyze
package manifest files (package.json, go.mod, requirements.txt). They miss
"shadow dependencies" — third-party components pulled in through:

- `curl | bash` installations
- direct binary downloads via curl/wget (GitHub releases, S3/GCS/Azure, CDNs)
- `npx` executions that download packages on-demand
- `npm install -g`, `pip install <url>`, `go install`, `cargo install`
- unpinned container images (`:latest`, `:main`)
- unpinned GitHub Actions (`@v4` instead of a commit SHA)
- MCP servers, agent plugins, and generated install instructions
- Homebrew, Scoop, and WinGet package catalog artifacts
- vendored binaries checked into repos
- non-standard Maven/Gradle/Helm repositories

**github-inventory** scans a repository and finds all of these, giving you
visibility into your actual supply chain attack surface. The Python package and
installed CLI use the same canonical name; the component source remains in the
`github-shadow-deps/` directory of the SupplyDrift monorepo.

## Installation

Prerequisites: Python 3.10+ and `git` (needed to scan GitHub URLs).

```bash
# Clone the SupplyDrift repository; this component lives in github-shadow-deps/
git clone <repo-url>
cd SupplyDrift/github-shadow-deps

# Install dependencies (no package installation required)
pip install -r requirements.txt

# Optional: install AI-powered analysis dependencies
pip install -r requirements-ai.txt
```

The base scanner is fully offline — only `requirements.txt` is needed.
`requirements-ai.txt` is optional and only required if you pass `--ai`.

You can also install it as a package: `pip install -e .` provides a
`github-inventory` console command equivalent to `python3 scan.py`.

## Quick Start

`scan.py` is a Click group; the scanning command is `scan`. Use `python3` if
your system doesn't symlink `python`.

```bash
# Scan the test fixtures to see what the tool detects
python3 scan.py scan tests/fixtures/

# Scan the current directory / a specific path
python3 scan.py scan .
python3 scan.py scan /path/to/repo

# Scan a GitHub repository (clones to a temp dir, scans, cleans up)
python3 scan.py scan https://github.com/org/repo

# Output as JSON, or as SARIF for GitHub Code Scanning
python3 scan.py scan . --format json
python3 scan.py scan . --format sarif -o results.sarif

# Only show HIGH and CRITICAL findings
python3 scan.py scan . --severity high

# Filter by category
python3 scan.py scan . --category cicd-tool --category script-installation

# CI integration: exit code 1 if any CRITICAL findings
python3 scan.py scan . --fail-on critical

# Consolidate findings by unique dependency
python3 scan.py scan . --group-by dep

# AI-powered analysis (optional runtime backend; set GITHUB_INVENTORY_AI_KEY)
python3 scan.py scan . --ai --ai-max-files 10

# AI + enrichment (recommendations per dependency)
python3 scan.py scan . --ai --enrich

# Get help
python3 scan.py --help
python3 scan.py scan --help
```

### CLI reference (`scan`)

| Flag | Default | Description |
|------|---------|-------------|
| `PATH_OR_URL` | `.` | Local repo path or GitHub URL (cloned to a temp dir). |
| `--format, -f {table,json,sarif}` | `table` | Output format. |
| `--output, -o FILE` | stdout | Write output to a file. |
| `--severity, -s {critical,high,medium,low}` | `low` | Minimum severity level to report. |
| `--category, -c NAME` | all | Only report findings in this category (repeatable — values below). |
| `--fail-on {critical,high,medium,low,never}` | `high` | Exit with code 1 if any finding is at or above this severity. |
| `--config PATH` | none | Path to an externally trusted `.github-inventory.yml` file. |
| `--trust-target-config` | off | Trust `PATH_OR_URL/.github-inventory.yml`; target policy may suppress findings. |
| `--group-by, -g {none,dep}` | `none` | `dep` consolidates findings by unique dependency. |
| `--width, -w N` | auto | Table output width in columns. |
| `--ai` | off | Enable AI-powered analysis (needs the optional AI SDK + API key). |
| `--ai-model ID` | see `--help` | AI model id used in `--ai` mode. |
| `--ai-max-files N` | `20` | Cap the number of files sent to the LLM in `--ai` mode. |
| `--enrich` | off | Enrich findings with AI-generated context. Requires `--ai`. |
| `--deep-lockfile` | off | Parse `package-lock.json` / `pnpm-lock.yaml` / `bun.lock` for transitive packages with install hooks. Slower; opt-in. |

Valid `--category` values (also the `category` field in JSON/SARIF output):
`script-installation`, `binary-download`, `unmanaged-package`,
`git-dependency`, `container-image`, `cicd-tool`, `vendored-binary`,
`build-external`, `script-reference`, `file-reference`, `embedded-script`,
`precommit-hook`, `devcontainer`, `tool-version-manager`, `registry-config`,
`cdn-reference`, `source-http-call`, `mcp-server`, `agent-plugin`,
`system-package-list`, `pulumi-resource`, `package-script`, `transitive-hook`.

## Features

- **26 specialized scanners** across shadow-dependency categories — script installs, binary downloads, unmanaged packages, git deps, container images, CI/CD, vendored binaries, build-system externals, MCP servers, agent plugin manifests, package catalogs, reference tracking, and more
- **Optional AI-powered analysis** (`--ai`) — LLM catches variable URLs, indirect execution, and novel patterns the regex layer misses; offline by default
- **Optional finding enrichment** (`--ai --enrich`) — adds dependency context and fix recommendations
- **Reference tracking** — automatically follows and scans scripts/files referenced from configs
- **Targeted docs scanning** — scans agent/MCP/install docs with dependency commands while avoiding broad README noise
- **Scan local repos or GitHub URLs** — clone and scan in one command
- **Multiple output formats** — table (human), JSON, SARIF (GitHub Code Scanning)
- **Severity-based filtering** — focus on CRITICAL/HIGH findings
- **Configurable ignore rules** — suppress known-good patterns
- **CI-friendly** — exit code based on severity threshold
- **Secret-safe** — pre-LLM sanitizer strips AWS keys, GitHub tokens, private keys, connection-string passwords before any network call

## Scanner Categories

1. **Script installations** (CRITICAL) — remote scripts piped to a shell:
   `curl … | bash`, `wget … | sh`, `bash <(curl …)`, `eval "$(curl …)"`.
2. **Binary downloads** (HIGH) — direct downloads that bypass manifests:
   `curl -o tool https://…`, GitHub releases, cloud storage (S3/GCS/Azure), CDNs.
3. **Unmanaged packages** (HIGH/MEDIUM/LOW) — installs outside manifests:
   `npm install -g`, `npx`, `pip install <url>`, `go install …@latest`,
   `brew`/`apt-get` in CI.
4. **Git dependencies** (MEDIUM) — `git clone`, `.gitmodules`,
   `pip install git+https://…`.
5. **Container images** (HIGH/MEDIUM) — unpinned/mutable images (`FROM node:latest`,
   `image: myapp:main`), images from non-standard registries.
6. **CI/CD tools** (CRITICAL/HIGH) — unpinned GitHub Actions
   (`@main` is CRITICAL, tag-pinned `@v4` is HIGH — pin by SHA), tool downloads
   in workflow `run:` blocks.
7. **Vendored binaries** (LOW/MEDIUM) — `.exe`/`.dll`/`.so`/`.dylib`/`.wasm`,
   `.jar`/`.class` files checked into the repo outside build directories.
8. **Build-system externals** (HIGH/MEDIUM) — Makefile downloads, non-standard
   Maven/Gradle repositories, Helm charts from untrusted registries, Terraform
   modules from git/http sources.
9. **Reference tracking** (HIGH/MEDIUM/LOW) — files referenced from CI `run:`
   blocks, Dockerfile `COPY`/`ADD`, docker-compose `build:`, Makefiles,
   package.json scripts, and Kubernetes ConfigMaps/command arrays are both
   *reported* (visibility) and *automatically scanned* when present (coverage),
   so shadow dependencies inside referenced scripts are detected.
10. **MCP servers and agent plugins** (HIGH/CRITICAL) — AI-tooling configs that
    launch external tools or install plugin capabilities: `.mcp.json`/`mcp.json`
    (and any JSON with `mcpServers`), servers run via `npx`/`pnpx`/`uvx`/`bunx`/
    `pnpm dlx`, remote MCP endpoints, Claude/Codex/Cursor/Copilot plugin
    marketplace sources, unpinned remote plugin sources, agent `SKILL.md`
    frontmatter (`allowed-tools`, `requires`/`install` metadata), and
    source-code strings that agent tools emit as actionable setup instructions.
11. **Package catalogs** (LOW/MEDIUM) — Homebrew formula `url` entries, Scoop
    manifest architecture URLs, and WinGet `InstallerUrl` entries that
    distribute installable artifacts outside application manifests.
    Checksummed entries are reported at lower severity than unchecked ones;
    these findings are emitted under the `binary-download` category.

Beyond these, dedicated scanners cover pre-commit hooks, devcontainers,
tool-version managers (`.tool-versions`, `.nvmrc`, …), registry configs
(`.npmrc`, `pip.conf`, …), CDN references, HTTP calls in source code,
mobile/native/JVM-BEAM ecosystem externals, system package lists, Pulumi IaC,
and package.json lifecycle scripts — the full set is registered in
[`src/github_inventory/scanners/__init__.py`](src/github_inventory/scanners/__init__.py).

## Configuration

Scanner policy is not loaded from the scanned repository by default. For
untrusted or remote targets, keep policy outside the target and pass its exact
path with `--config /trusted/policy.yml`. For a repository you control, use
`--trust-target-config` to explicitly load its root `.github-inventory.yml`;
the CLI prints a warning because target-owned policy can suppress findings.

An example policy:

```yaml
version: 1

# Ignore specific patterns (regex)
ignore:
  - pattern: "https://dl.google.com/go/.*"
    reason: "Official Go downloads"
  - pattern: "actions/checkout@v4"
    reason: "Widely-used action, tag acceptable for us"

# Exclude paths from scanning
exclude_paths:
  - "vendor/**"
  - "third_party/**"
  - "**/*.min.js"

# Override severity for specific patterns
severity_overrides:
  unpinned-github-action:
    severity: critical  # Treat tag-pinned actions as CRITICAL instead of HIGH
  brew-install-ci:
    severity: medium    # Escalate brew installs

# Additional trusted container registries
trusted_registries:
  - "internal-registry.company.com"
  - "*.corp.example.com"
```

## Output Formats & Exit Codes

**Table** (default) — human-readable, color-coded by severity.

**JSON** — structured output for programmatic consumption:

```json
{
  "version": "0.1.0",
  "tool": "github-inventory",
  "summary": {
    "total_findings": 42,
    "files_scanned": 156,
    "scan_duration_ms": 342.5,
    "by_severity": {"critical": 3, "high": 12, "medium": 20, "low": 7},
    "by_category": {"script-installation": 3, "cicd-tool": 8}
  },
  "findings": []
}
```

Each finding carries `file`, `line`, `category`, `severity`, `pattern_id`,
`matched_text`, `extracted_dep`, and `description` (plus `analysis_source`,
`confidence`, and `enrichment` when AI produced or enriched it). Example
recipes:

```bash
# Complete dependency inventory
python3 scan.py scan . --format json | \
  jq '.findings[] | {file: .file, dep: .extracted_dep, severity: .severity}'

# All CRITICAL curl|bash findings
python3 scan.py scan . --category script-installation --severity critical \
  --format json | jq '.findings[] | select(.pattern_id == "curl-pipe-bash")'
```

**SARIF** — SARIF 2.1.0 for GitHub Code Scanning integration
(`--format sarif -o results.sarif`).

Exit codes:

- `0` — Success, no findings above the fail threshold
- `1` — Found issues at or above the `--fail-on` threshold
- `2` — Runtime error (invalid path, git clone failure, etc.)

## CI Integration

### GitHub Actions

```yaml
name: Supply Chain Security

on: [push, pull_request]

jobs:
  shadow-deps:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<SHA>

      - name: Set up Python
        uses: actions/setup-python@<SHA>
        with:
          python-version: '3.10'

      - name: Clone the scanner (lives in the SupplyDrift monorepo)
        run: |
          git clone <repo-url> /tmp/SupplyDrift
          pip install -r /tmp/SupplyDrift/github-shadow-deps/requirements.txt

      - name: Scan for shadow dependencies
        run: python /tmp/SupplyDrift/github-shadow-deps/scan.py scan . --format sarif -o results.sarif --fail-on high

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@<SHA>
        if: always()
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
shadow-deps:
  image: python:3.10
  before_script:
    - git clone <repo-url> /tmp/SupplyDrift
    - pip install -r /tmp/SupplyDrift/github-shadow-deps/requirements.txt
  script:
    - python /tmp/SupplyDrift/github-shadow-deps/scan.py scan . --format json -o shadow-deps.json --fail-on high
  artifacts:
    reports:
      codequality: shadow-deps.json
```

## AI-Powered Analysis (optional)

Pass `--ai` to layer LLM-based detection on top of the regex scanners. This
catches patterns the regex layer can't reach (variable-constructed URLs,
indirect execution, novel package managers).

```bash
# Set your AI API key — GITHUB_INVENTORY_AI_KEY is checked first,
# then ANTHROPIC_API_KEY as a fallback.
export GITHUB_INVENTORY_AI_KEY=...

# AI-augmented scan
python3 scan.py scan . --ai

# Lower the per-scan API cost
python3 scan.py scan . --ai --ai-max-files 5

# Add vulnerability context (what is this dep? known risks? fix?)
python3 scan.py scan . --ai --enrich
```

AI findings are tagged `analysis_source: "ai-assisted"` in JSON/SARIF and
shown with an `AI` badge in the table view. Each carries a `confidence`
score; only findings above 0.7 are reported.

### Security model

- **Offline by default.** Without `--ai`, no network calls are made and the
  optional AI SDK is not even imported.
- **Secrets are stripped before any LLM call.** A pre-processing sanitizer
  redacts AWS keys, GitHub tokens, generic API keys/passwords, private key
  blocks, and connection-string passwords. See `src/github_inventory/sanitizer.py`.
- **No URL fetches.** Enrichment data comes from the model's training
  knowledge — the tool never fetches URLs found in scanned code.
- **Cost-bounded.** `--ai-max-files` caps the number of files sent to the
  LLM. Internally rate-limited to 10 calls/minute with exponential backoff.
- **Failures are soft.** Missing API key or missing SDK → AI is skipped, the
  regex scan still produces output.

### When to use what

| Mode                       | What it adds                                              |
|----------------------------|-----------------------------------------------------------|
| `python3 scan.py scan .`   | Fast, free, deterministic. Good default for CI gates.     |
| `... --ai`                 | Catches variable/indirect/novel patterns regex misses.    |
| `... --ai --enrich`        | Adds 1-line summary + risks + fix per unique dependency.  |

## Platform sync (`gbom_sync.py`)

Beyond the standalone CLI, `gbom_sync.py` enumerates an org/user's repositories
(or an explicit list), scans each, and **syncs the results to the SupplyDrift
platform**. Each repo scan runs **three** engines, deduped into one payload:

1. the **phantom-dependency** engine (non-manifest deps → a component *and* a
   finding per detection);
2. **syft** over the clone (`dir:`) → declared dependencies as components;
3. **grype** over the syft SBOM → **CVE findings** with `fix_recommendation`.

syft/grype are optional (`scanner.scan_sbom` / `scan_vulnerabilities`, default on
when the binaries are present; baked into the
[runner image](./deploy/runner.Dockerfile)) — without them the scan still ships
phantom-dependency findings.

In the Compose runner, each repository/SBOM invocation gets a fresh, mandatory
`nono` capability sandbox with block-all networking, a minimal environment, and
only the cloned target or temporary SBOM plus the immutable Grype DB readable.
The runner token and all other parent credentials remain outside the sandbox;
application code and the database are root-owned/read-only. Local source-tree
runs default to compatibility mode and warn if `nono` is unavailable.

```bash
# Local, one repo -> JSON file (no platform, no config; auto --no-push)
python3 gbom_sync.py ./my-repo -o result.json             # a local checkout
python3 gbom_sync.py octocat/Hello-World -o result.json   # a github slug (clones it)
python3 gbom_sync.py ./my-repo -o report.json --report    # flattened report
python3 gbom_sync.py ./my-repo -o out.json --malware      # + OSV malicious-package (MAL-*) check

# Connected: public repos, no credentials
python3 gbom_sync.py --config sync.example.yaml --dry-run        # list repos
python3 gbom_sync.py --config sync.example.yaml                  # clone -> scan -> push

# Fetch the source list from the platform (UI-managed), JSON logs for cron:
python3 gbom_sync.py --config-url http://platform:8765/api/scanner/config --log-format json

# Runner mode: long-running worker that executes scans the UI "Scan" button queues
python3 gbom_sync.py --serve --config-url http://platform:8765/api/scanner/config
```

`result.json` is the normalized platform payload; `--report` emits `{target,
components, vulnerabilities:[{id,severity,package,version,fix}], issues:[…phantom-deps]}`.

| Flag | Description |
|------|-------------|
| `REPO …` | Repo path or GitHub URL/owner-repo to scan locally (no platform or config needed) |
| `--config FILE` | YAML config (see [`sync.example.yaml`](./sync.example.yaml)) |
| `--config-url URL` | Fetch the config from the platform (`…/api/scanner/config`) |
| `--source NAME` | Only run the named source(s) (repeatable) |
| `--dry-run` | List repositories only; do not clone/scan |
| `--no-push` | Scan but do not POST to the platform |
| `--format {summary,json}` | Result output style |
| `-o, --output FILE` | Write the output to a file |
| `--report` | Local mode: flattened `{target, components, vulnerabilities, issues}` JSON |
| `--malware` | Local mode: also check scanned packages against OSV's malicious-package (`MAL-*`) feed |
| `--serve` | Runner mode: poll the platform for queued github scan jobs and run them |
| `--poll-interval SECONDS` | Runner mode: seconds between polls when the queue is empty (default 15) |
| `--once` | Runner mode: process at most one job, then exit (for cron / tests) |
| `-v, --verbose` / `-q, --quiet` | Log verbosity |
| `--log-format {text,json}` | Progress log format |

Auth is **optional** — omit it (or list explicit public `repositories`) to scan
public repos anonymously; a classic PAT is needed only for private repos and is
referenced by env-var name. Results POST to the platform's
`POST /api/sync/repositories` — payload shape in
[`platform/connector_contract.md`](../platform/connector_contract.md).

## How It Works

1. **File Discovery** — Walks the repository, classifying files (CI workflows, scripts, Dockerfiles, k8s/Helm, build files, package configs, targeted agent/install docs, MCP configs, package catalogs, etc.) via `FILE_RULES` and content-based heuristics in `discovery.py`.
2. **Scanner Execution (Phase 1)** — Reads each text file once; runs the registered regex-based scanners against the joined content.
3. **Regex Reference Resolution (Phase 1.5)** — Extracts file references from `SCRIPT_REFERENCE`/`FILE_REFERENCE` findings and scans the referenced files too, so shadow deps inside referenced scripts aren't missed.
4. **AI Reference Resolution (Phase 1.6, optional)** — With `--ai`, an LLM enumerates files/URLs that variable-constructed references (`$SCRIPT_DIR/...`, `source <(...)`) would resolve to at runtime; resolved files re-enter the regex pipeline.
5. **Binary Detection (Phase 2)** — Separate pass over binary file extensions for `VendoredBinaryScanner`.
6. **AI Analysis (Phase 2.5, optional)** — With `--ai`, the LLM analyzes candidate snippets the regex layer flagged as ambiguous (or missed entirely), with sanitization, rate-limiting, and a 0.7 confidence floor.
7. **Deep Lockfile Analysis (Phase 2.7, optional)** — With `--deep-lockfile`, parses lockfiles for transitive packages with install hooks.
8. **Filtering (Phase 3)** — Applies ignore rules and severity overrides only from explicitly trusted configuration.
9. **Dedup + Merge (Phase 3.5–4)** — Drops AI findings that overlap a regex hit (±1 line, same category); deduplicates by `(file, line, pattern_id)`.
10. **Enrichment (Phase 5, optional)** — With `--ai --enrich`, batches findings by `extracted_dep` and asks the LLM for a summary, known supply-chain risks, and a fix recommendation.
11. **Reporting** — Severity-sorted output in the requested format. AI/enrichment fields are emitted only when present, so consumers of the regex-only path see the same shape they always did.

## Development

```bash
# From github-shadow-deps/, with requirements installed:
pip install -r requirements-dev.txt

# Optional: AI dependencies for testing --ai code paths
pip install -r requirements-ai.txt

# Run tests (pytest is configured with pythonpath=src in pyproject.toml)
pytest

# Run on synthetic fixtures
python3 scan.py scan tests/fixtures/

# Run the full regression suite (offline + AI if key set + secret-leak audit)
./scripts/regression.sh

# Check code quality
ruff check src/ tests/
```

## License

Apache License 2.0 — see the repository [LICENSE](../LICENSE).

## Contributing

Contributions welcome! See the repository
[CONTRIBUTING.md](../CONTRIBUTING.md), and please open an issue or PR.

## Acknowledgments

Inspired by the gap left by traditional SCA tools and informed by:
- [SLSA Framework](https://slsa.dev/)
- [OSSF Scorecard](https://github.com/ossf/scorecard)
- [Semgrep Supply Chain](https://semgrep.dev/docs/semgrep-supply-chain/)
