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

For a **local directory**, the base scanner is offline: it reads the checkout
and makes no network requests. `scan.py` accepts a GitHub URL (not a bare
`owner/repo` slug) and first uses `git` to clone it, so that path requires
network access. The platform-oriented `gbom_sync.py` accepts either form.
`requirements-ai.txt` is optional and only required if you pass `--ai`, which
calls the configured LLM service.

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
| `--ai-max-files N` | `20` | Cap files sent to the primary AI analyzer; reference resolution and enrichment have separate limits. |
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
- **Optional AI-powered analysis** (`--ai`) — LLM catches variable URLs, indirect execution, and novel patterns the regex layer misses; local-directory regex scans are offline by default
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
    when: always
    paths:
      - shadow-deps.json
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

- **Local scans are offline by default.** Without `--ai`, scanning a local
  directory makes no network calls and the optional AI SDK is not imported.
  A GitHub URL still requires a network clone before scanning.
- **Secrets are stripped before any LLM call.** A pre-processing sanitizer
  redacts AWS keys, GitHub tokens, generic API keys/passwords, private key
  blocks, and connection-string passwords. See `src/github_inventory/sanitizer.py`.
- **No target-URL fetches.** The AI layer does not fetch URLs found in scanned
  code; enrichment comes from the model. This does not include the explicit
  GitHub clone requested when the scan target itself is a URL.
- **Stage-specific cost controls.** `--ai-max-files` caps only the primary AI
  analyzer, whose calls are limited to 10/minute with exponential backoff. AI
  reference resolution may make up to 10 additional calls per scan. Enrichment
  sends at most 10 unique dependencies per request, so its call count grows
  with the number of unique dependencies. Those latter stages do not share the
  primary analyzer's per-minute limiter.
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
platform**. Each repo scan combines up to **three** engines into one payload:

1. the **phantom-dependency** engine (non-manifest deps → a component *and* a
   finding per detection);
2. **syft** over the clone (`dir:`) → declared dependencies as components;
3. **grype** over the syft SBOM → **CVE findings** with `fix_recommendation`.

syft/grype are optional (`scanner.scan_sbom` / `scan_vulnerabilities`, default on
when the binaries are present; baked into the
[runner image](./deploy/runner.Dockerfile)) — without them the scan still ships
phantom-dependency findings.

The security boundary has two layers in the reference Compose deployment:

- The long-running runner is non-root, drops all Linux capabilities, enables
  `no-new-privileges`, and has a read-only container filesystem. Repository
  discovery, cloning, the Python phantom-dependency engine, and platform
  uploads run in this parent process; its temporary clones live on `/tmp`
  tmpfs and these operations necessarily retain network access.
- Each **Syft and Grype subprocess** gets a fresh, mandatory `nono` capability
  sandbox. It receives a minimal environment, block-all networking, and only
  the cloned target or temporary SBOM plus the immutable Grype DB as readable
  inputs. The GitHub PAT, platform runner token, and other parent credentials
  are not passed into those tool sandboxes.

The Python phantom-dependency engine itself is not wrapped by `nono`. Local
source-tree runs use sandbox `auto` mode for Syft/Grype: they warn and run those
tools without filesystem isolation if `nono` is unavailable. Set
`SUPPLYDRIFT_TOOL_SANDBOX=required` to fail closed like the Compose runner.

```bash
# Local, one repo -> JSON file (no platform, no config; auto --no-push)
python3 gbom_sync.py ./my-repo -o result.json             # a local checkout
python3 gbom_sync.py octocat/Hello-World -o result.json   # a github slug (clones it)
python3 gbom_sync.py ./my-repo -o report.json --report    # flattened report
python3 gbom_sync.py ./my-repo -o out.json --malware      # + networked OSV malicious-package (MAL-*) check

# Public GitHub discovery needs no GitHub PAT; dry-run does not push to the platform
python3 gbom_sync.py --config sync.example.yaml --dry-run

# Pushing with a local config to an auth-enabled platform needs a UI-minted
# ingest token in a protected file
SUPPLYDRIFT_RUNNER_TOKEN_FILE=/secure/path/supplydrift-ingest.token \
  python3 gbom_sync.py --config sync.example.yaml

# Fetch UI-managed sources from an auth-enabled platform. External runners need
# a UI-minted runner-scope token in a protected file.
SUPPLYDRIFT_RUNNER_TOKEN_FILE=/secure/path/supplydrift-runner.token \
  python3 gbom_sync.py --config-url https://supplydrift.example/api/scanner/config --log-format json

# Runner mode: long-running worker that executes scans the UI "Scan" button queues
SUPPLYDRIFT_RUNNER_TOKEN_FILE=/secure/path/supplydrift-runner.token \
  python3 gbom_sync.py --serve --config-url https://supplydrift.example/api/scanner/config
```

The reference Compose runner already reads its generated token from the shared
`/run/supplydrift/runner.token` volume and uses the private Compose network; no
manual token export is needed there. The `--malware` option sends package PURLs,
or fallback ecosystem/name/version coordinates, to OSV's `/v1/querybatch`
service. OSV network failures are soft: the base scan still completes.

Local output is always a JSON array, including for one repository. Each element
of `result.json` is a normalized platform payload and can be submitted
individually to `/api/ingest`; the array wrapper itself cannot. `--report` emits
an array of flattened `{target, components,
vulnerabilities:[{id,severity,package,version,fix}], issues:[…phantom-deps]}`
objects for people and is not re-ingestable.

| Flag | Description |
|------|-------------|
| `REPO …` | Repo path or GitHub URL/owner-repo to scan locally (no platform or config needed) |
| `--config FILE` | YAML config (see [`sync.example.yaml`](./sync.example.yaml)) |
| `--config-url URL` | Fetch the config from the platform (`…/api/scanner/config`) |
| `--source NAME` | Only run the named source(s) (repeatable) |
| `--dry-run` | List repositories only; do not clone/scan |
| `--no-push` | Scan but do not POST to the platform |
| `--format {summary,json}` | Result output style in config-driven mode; local-target mode always writes JSON |
| `-o, --output FILE` | Write the output to a file |
| `--report` | Local mode: array of flattened `{target, components, vulnerabilities, issues}` objects |
| `--malware` | Local mode: submit package coordinates to OSV and add malicious-package (`MAL-*`) matches; network failures are soft |
| `--serve` | Runner mode: poll the platform for queued github scan jobs and run them |
| `--poll-interval SECONDS` | Runner mode: seconds between polls when the queue is empty (default 15) |
| `--once` | Runner mode: process at most one job, then exit (for cron / tests) |
| `-v, --verbose` / `-q, --quiet` | Log verbosity |
| `--log-format {text,json}` | Progress log format |

There are two separate credentials:

- **GitHub authentication is optional for public repositories.** A classic PAT
  is needed for private repositories (and may help with API rate limits). Local
  YAML references the PAT by environment-variable name, so the value stays in
  the runner environment. UI-managed connectors store the submitted value in
  encrypted platform secret storage and reveal it only in an authorized runner
  configuration response.
- **SupplyDrift authentication is on by default.** `--config-url` and `--serve`
  require a `runner`-scope bearer token because the runner fetches decrypted
  connector credentials, claims jobs, completes them, and ingests results. The
  client resolves `SUPPLYDRIFT_RUNNER_TOKEN` first, then
  `SUPPLYDRIFT_RUNNER_TOKEN_FILE` (default
  `/run/supplydrift/runner.token`). A local config-file run that only pushes
  results can use an `ingest`-scope token, but that token cannot fetch scanner
  config or claim queue jobs.

For a claimed job, the serve loop includes that job's `connector_id` in its
config request. The response still contains the topology of all enabled
connectors, but secret values are revealed only for the claimed connector and
masked for the others. A direct `--config-url` run fetches all enabled connector
configuration, even when `--source` later limits execution, and a runner token
can deliberately omit or change connector scoping. Treat every runner token as
globally authorized to retrieve stored connector secrets.

Results POST to the platform's `POST /api/sync/repositories`; see the payload
and authorization contract in
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
9. **Dedup + Merge (Phase 3.5–4)** — Drops AI findings that overlap a regex hit (±1 line, same category); deduplicates by `(file_path, line_number, pattern_id, extracted_dep)`.
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
