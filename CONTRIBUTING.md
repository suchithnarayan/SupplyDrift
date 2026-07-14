# Contributing to SupplyDrift

Thanks for your interest in contributing! SupplyDrift is a small monorepo of
supply-chain / phantom-dependency security tooling. This guide covers the whole
project; some components have their own, stricter guides linked below.

By participating you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Repository layout

| Path | What it is | Language |
| --- | --- | --- |
| `platform/` | React UI + FastAPI API (MySQL in compose, SQLite for dev) — aggregates every source; auth, scans, vuln/malware views | Python 3.12+, TypeScript/React |
| `github-shadow-deps/` | Repository-level phantom-dependency scanner (CLI package `github-inventory`) | Python 3.10+ |
| `image-scanner/` | Container/registry SBOM scanner, Kubernetes/EKS topology scanner, and ECS running-image discovery | Python 3.10+ |
| `endpoint-dep-inventory/` | Syft-based endpoint SBOM collector (bash) | Bash 3.2+ |
| `supplydrift-sandbox/` | Shared per-invocation Syft/Grype capability boundary used by the hardened runners | Python 3.10+ |

The collector is a single portable bash script with strict compatibility rules —
see [Endpoint collector house rules](#endpoint-collector-house-rules-bash) below
before touching it.

## Development setup

Install the tools the CI uses (all optional stages are skipped if a tool is
missing): `python3` (3.10+, 3.12+ for the platform), `node`/`npm` (20.19+ or
22.12+, only to build the UI), `git`, and — for the collector's smoke tests —
`syft`, `grype`, `jq`, and `shellcheck`.

Enable the secret-scanning pre-commit hook (recommended):

```bash
pip install pre-commit && pre-commit install   # runs gitleaks on every commit
```

## Running the checks

The umbrella check covers the platform, image scanner, repository scanner,
frontend, and endpoint collector: a fresh venv, three pytest suites, the frontend
typecheck/build, and the collector's shell checks. The sandbox suite is currently
separate and must also be run for a complete repository check:

```bash
bash ci.sh            # run the umbrella checks (reuses .ci-venv if present)
bash ci.sh --fresh    # wipe the venv + frontend node_modules/dist first
(cd supplydrift-sandbox && python -m pytest)
```

Per-component, once dependencies are installed:

```bash
(cd platform            && python -m pytest)
(cd image-scanner       && python -m pytest)
(cd github-shadow-deps  && python -m pytest && ruff check .)
(cd supplydrift-sandbox && python -m pytest)
```

Other useful scripts:

- `platform/smoke.sh` — boots a throwaway platform instance and exercises the API.
- `github-shadow-deps/scripts/regression.sh` — fixture-based scanner regression run.
- `e2e-cli.sh` — end-to-end CLI flow across the components (needs `syft`, `grype`,
  `jq`, `curl`, `python3`, and network access for dependencies and the test image).

## Endpoint collector house rules (bash)

`endpoint-dep-inventory/collect-sbom-inventory.sh` targets macOS's stock
bash 3.2 and BSD userland. These rules take precedence for that directory.

Run the collector's validation suite before every PR that touches it (CI runs
the same suite on Ubuntu **and macOS** — both must pass):

```bash
cd endpoint-dep-inventory
bash -n collect-sbom-inventory.sh
bash -n sbom-inventory.env.example
bash -n sbom-inventory.supplydrift.env.example
shellcheck collect-sbom-inventory.sh tests/collector-smoke.sh
python3 -m py_compile sbom-dummy-server.py
./tests/collector-smoke.sh
```

Style rules:

- **Never reuse bare variable names across functions** (`root`, `elapsed`,
  `delay`, …). Older core functions use unique prefixes instead of `local`
  (e.g. `gd_` in `gate_decide_root`, `sr_` in `scan_root`); newer functions use
  `local`. Either is acceptable for new code — pick one per function and keep
  it bash-3.2-clean.
- **No bash-4+ features**: no `mapfile`, `declare -A`, `${var,,}`, `&>>`.
- **BSD + GNU portability**: only POSIX-era `find` primaries
  (`-path -prune -name -type -newer -maxdepth -print -o`); use
  `| head -n 1` for short-circuiting, never `-quit`; no `date -d`/`date -r`
  conversions (store timestamps in the format you need at write time);
  prefer `[ file1 -nt file2 ]` over `stat`.
- **stdout is a contract**: dry-run batch JSON and heartbeat documents are
  the only stdout. ALL human-readable output goes through `emit`/`log`/`vlog`
  (stderr). The smoke test asserts stdout purity and that non-TTY stderr
  contains no carriage returns.
- **`set -e` is live at top level**: gated helpers end with `|| return 0`
  guards; reads use `|| true`; predicates are only called inside `if`;
  counters use `x=$((x+1))`, never `((x++))`.
- **Pipeline subshells lose state**: never mutate counters or globals inside
  `... | while read` loops.
- **shellcheck must stay clean** with targeted `# shellcheck disable=` lines
  only where a rule is a false positive, with a comment saying why.

Collector PR expectations:

- Every new `SBOM_*` knob needs: a `set_defaults` entry, validation in
  `validate_config` where applicable, a `usage()` line, a README config-table
  row, and an entry or comment in `sbom-inventory.env.example`.
- Behavior changes need smoke-test coverage in `tests/collector-smoke.sh`.
  The existing tests are deterministic and offline — keep yours that way
  (fixture roots under `test-manifests/`, seeded gate state, dry runs).
- Changes to the default exclude lists must respect the guarded keeps
  (`/etc`, `/opt`, `/usr/local`, `/usr/lib`, `/var/lib/dpkg`, macOS data
  volume) — the smoke test fails if these ever appear in the defaults — and
  must document the rationale in
  `endpoint-dep-inventory/docs/scan-scope.md`.
- Update `endpoint-dep-inventory/CHANGELOG.md`.

## Submitting changes

1. Branch from `main` and keep changes focused.
2. Add or update tests for behaviour changes; make sure `bash ci.sh` has no `FAIL` rows.
3. Do **not** commit secrets or real inventory/SBOM data. The gitleaks pre-commit
   hook and the `secret-scan` CI workflow guard against this.
4. Open a pull request using the template and describe which component(s) you touched.

## Security

Please report vulnerabilities privately — do **not** open a public issue. See
[`SECURITY.md`](SECURITY.md) for the process and scope.

## License

By contributing, you agree that your contributions are licensed under the
Apache License, Version 2.0 (see [`LICENSE`](LICENSE)).
