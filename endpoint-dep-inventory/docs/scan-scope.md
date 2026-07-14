# Scan Scope & Default Excludes

What the collector scans, what it skips, and why. For the configuration
reference see the [README](../README.md#configuration).

## Default scope and the full-filesystem opt-in

The default scan scope is **user home directories** — `/home` on Linux,
`/Users` on macOS — where developer dependency evidence lives. This keeps
scans fast and light on the endpoint. The trade-off: OS-level packages
(dpkg/rpm/apk, Homebrew), `/opt`, and `/usr/local` are not inventoried in
this mode. For full coverage, opt into full-filesystem scans:

```bash
SBOM_SCAN_ROOTS="/"
SBOM_SCAN_POLICY_VERSION="fullfs-v1"
```

## Tiered default excludes

When `SBOM_EXCLUDE_PATHS` is empty, the collector applies tiered built-in
excludes selected per scan root (see `effective_excludes_for_root` in the
script). Set `SBOM_EXCLUDE_PATHS` to replace them for every root, or
`SBOM_USE_DEFAULT_EXCLUDES=false` to scan with none.

| Scan root | Default excludes applied |
| --- | --- |
| `/` | The full OS-aware list below. |
| `/home` or `/Users` (the default scope) | Universal tier + the home cache tier applied per user (`./*/go/pkg/mod`, `./*/.cargo/registry`, `./*/.cache`, ...). |
| A home directory itself (`/home/<user>`, `/Users/<user>`, `/root`) | Universal tier + home cache tier (`~/.cache`, `~/go/pkg/mod`, `~/.cargo/registry`, npm `_cacache`, conda `pkgs/`, and on macOS the Library cache/cloud/Developer paths). |
| Any other root (project dirs, `/opt/app`, ...) | Universal tier only: `**/.git/**`, `**/.hg/**`, `**/.svn/**`, `**/__pycache__/**`, `**/node_modules/.cache/**` — names that can never hold dependency evidence. |

Root-anchored system patterns (`./proc/**`, `./tmp/**`, ...) are never applied
to non-`/` roots, where they would wrongly match project paths like
`myproject/tmp`.

## What the defaults exclude, and why

| Group | Paths | Rationale |
| --- | --- | --- |
| Pseudo/tmp/caches | `/proc /sys /dev /run /tmp /var/tmp /var/log /var/cache ~/.cache` (Linux); `/private/tmp /private/var/tmp /private/var/log /private/var/folders /Library/Caches ~/Library/Caches ~/Library/Logs` (macOS) | No dependency evidence; high churn. |
| VCS internals | `**/.git/**`, `**/.hg/**`, `**/.svn/**` | Object stores are compressed blobs Syft cannot parse — pure traversal waste, zero coverage loss. Often the largest inode population on a developer machine. |
| Bytecode/bundler caches | `**/__pycache__/**`, `**/node_modules/.cache/**` | Derivatives of files sitting right next to them; `node_modules` itself stays scanned. |
| Container storage | `/var/lib/docker`, `/var/lib/containerd`, `/var/lib/containers`, `~/.local/share/containers`, `~/.docker/desktop` | Each layer is a full OS filesystem. Image contents are covered by the SupplyDrift image scanner; host-side scanning duplicates it and misattributes container packages to the endpoint. |
| Snap / Flatpak | `/snap`, `/var/lib/snapd`, `/var/lib/flatpak`, `~/.local/share/flatpak` (+ `squashfs` mounts skipped) | Read-only app images, duplicated per revision. App presence still surfaces via OS package databases. |
| System documentation | `/usr/share/doc`, `/usr/share/man`, `/usr/share/locale`, `/usr/src`, `/usr/include`, `/usr/share/go-*` (toolchain stdlib), `/usr/lib/firmware`, `/var/lib/apt/lists` | The dpkg/rpm/apk database is the OS-package evidence (and `/var/lib/dpkg` is never excluded); these are docs, headers, and repo index mirrors. |
| Download caches | `~/.npm/_cacache`, `~/.cargo/registry`, `~/go/pkg/mod` (full GOMODCACHE), pnpm store, conda `pkgs/` | Caches of everything ever fetched, not what is installed/used. Usage evidence stays in lockfiles (`go.mod`/`go.sum`, `Cargo.lock`), installed binaries in `~/go/bin` (embedded module metadata), conda `envs/`, and project trees. `~/.m2` is deliberately kept (Maven has no lockfile). |
| Cloud placeholders (macOS) | `~/Library/CloudStorage`, `~/Library/Mobile Documents` | Traversal can **hydrate** cloud files — downloading gigabytes and directly impacting the user. Never scan these. |
| macOS sealed system | `/System/Library`, `/System/Applications`, `iOSSupport`, `DriverKit`, `Cryptexes`, `/Library/Developer/CommandLineTools`, `.Spotlight-V100`, `.fseventsd`, `.DocumentRevisions-V100` | Apple-signed, SIP-immutable OS content and index databases. `/Applications` and all of `/System/Volumes/Data` remain scanned. |
| macOS user library | `~/Library/Containers`, `Group Containers`, `Application Support`, `Mail`, `Photos Library.photoslibrary`, `Developer/CoreSimulator`, `Xcode/DerivedData`, `iOS DeviceSupport` | Huge file counts, little to no dependency evidence, privacy-sensitive. |
| Foreign/removable mounts | `/mnt`, `/media` (+ `9p`/`drvfs` filesystem types skipped) | USB drives, backup disks, and WSL's Windows `C:` drive (millions of files) are not the endpoint's own inventory. To scan one deliberately, list it in `SBOM_SCAN_ROOTS`. |
| Boot/spool/system noise | `/boot`, `/lost+found`, `/var/spool`, `/var/crash`, `/var/backups`, `/usr/share/{icons,fonts,zoneinfo}`; macOS `/cores`, `/private/var/db`, `/Library/Apple`, `/Library/Updates`, `/Library/Application Support` | Kernels, dumps, spools, asset forests, and Apple-managed databases (dyld caches) — all covered by OS package records or carrying no dependency evidence. The gate's pkg-receipt watch checks paths directly and is unaffected. |
| VM images | `/var/lib/libvirt/images` | Opaque disk images. |

## Deliberately not excluded

Kept in scope despite their size: `~/.nvm` and VS Code extension/server
directories (globally-installed npm packages live inside them, and extensions
are a real attack vector), `~/.m2` (often the only Maven install evidence),
`~/.pyenv` (its `site-packages` are real installs), `**/.terraform/**`
(provider binaries are supply-chain artifacts), `/etc` (syft reads
`os-release` for distro identity in PURLs), `/usr/lib`
(`python3/dist-packages` is real pip evidence), `/usr/share/nodejs`
(distro-packaged npm modules — their `package.json`s give npm-level PURLs that
dpkg names like `node-lodash` obscure), `~/go/bin` (installed Go binaries with
embedded module metadata), `/opt` (third-party installs including
`/opt/homebrew`), and `/srv`, `/usr/local`, `/Applications`.

## Writing your own excludes

These trade-offs are deliberate; re-include anything by setting
`SBOM_EXCLUDE_PATHS` explicitly (which replaces the defaults entirely). If you
provide your own list, keep directory patterns root-anchored:

```bash
SBOM_EXCLUDE_PATHS="./proc/**:./sys/**:./dev/**:./run/**:./tmp/**:./var/tmp/**:./var/log/**:./var/cache/**:**/.git/**"
```

Avoid active excludes such as:

```text
**/tmp/**
**/var/tmp/**
**/proc/**
**/sys/**
```

Those are relative globs and can match legitimate project paths under a user's
home directory.

Do not exclude dependency-bearing paths by default:

- `node_modules`
- `.venv`, `venv`, virtualenv directories
- `site-packages`
- `vendor`
- `.m2`, `.gradle`, `.cargo`, `.nuget`, `go/pkg/mod`
- `target`, `build`, `dist`

Those directories can contain installed dependency evidence. Exclude them only
if the organization intentionally chooses manifest-only inventory.
