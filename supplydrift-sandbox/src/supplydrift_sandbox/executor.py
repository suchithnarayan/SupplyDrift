"""Ephemeral capability sandboxes for Syft and Grype.

Every invocation gets a fresh HOME, cache, temporary directory, and nono
capability manifest.  Only the selected executable, its runtime libraries,
explicit inputs, the job directory, and CA/name-resolution files are visible.

``SUPPLYDRIFT_TOOL_SANDBOX`` controls local compatibility:

* ``required``: nono 0.67.1 and the filesystem canary must pass (hosted mode).
* ``auto``: use the sandbox when available; otherwise warn and run locally.
* ``off``: explicitly disable it for local development only.

``SUPPLYDRIFT_SANDBOX_NETWORK`` is ``require`` or ``best-effort``.  A proxy
policy that cannot start falls back to unrestricted egress only in best-effort
mode.  Blocked-network jobs never receive that fallback.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import sys
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Iterable, Mapping, Sequence
from urllib.parse import urlsplit

EXPECTED_NONO_VERSION = "0.67.1"

_MODE_VALUES = {"required", "auto", "off"}
_NETWORK_MODE_VALUES = {"require", "best-effort"}
_TOOL_ENV: dict[str, frozenset[str]] = {
    "syft": frozenset(
        {
            "SYFT_CHECK_FOR_APP_UPDATE",
            "SYFT_REGISTRY_AUTH_AUTHORITY",
            "SYFT_REGISTRY_AUTH_TOKEN",
            "SYFT_REGISTRY_AUTH_USERNAME",
            "SYFT_REGISTRY_AUTH_PASSWORD",
            "SYFT_REGISTRY_INSECURE_USE_HTTP",
        }
    ),
    "grype": frozenset(
        {
            "GRYPE_CHECK_FOR_APP_UPDATE",
            "GRYPE_DB_AUTO_UPDATE",
            "GRYPE_DB_CACHE_DIR",
        }
    ),
}
_SECRET_ENV = frozenset(
    {
        "SYFT_REGISTRY_AUTH_TOKEN",
        "SYFT_REGISTRY_AUTH_PASSWORD",
    }
)
_BASE_ENV = frozenset(
    {
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "PATH",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "TZ",
    }
)
_SAFE_TOOL_NAME = re.compile(r"^[A-Za-z0-9._-]+$")
_NONO_VERSION_RE = re.compile(r"^nono\s+([0-9]+\.[0-9]+\.[0-9]+)$")

# These locations may belong to the parent runner, but never to an untrusted
# cataloguer.  A repository path that resolves inside one is rejected too.
_READ_FORBIDDEN = (
    Path("/run/supplydrift"),
    Path("/home/app/.aws"),
    Path("/home/app/.kube"),
    Path("/home/app/.docker"),
    Path("/proc"),
)
_WRITE_FORBIDDEN = _READ_FORBIDDEN + (
    Path("/app"),
    Path("/opt/grype-db"),
    Path("/etc"),
    Path("/usr"),
    Path("/lib"),
    Path("/lib64"),
    Path("/proc"),
    Path("/sys"),
)


class NetworkPolicy(str, Enum):
    """Network behavior requested for one tool invocation."""

    BLOCKED = "blocked"
    PROXY = "proxy"
    UNRESTRICTED = "unrestricted"


class SandboxError(RuntimeError):
    """Base error for sandbox configuration and enforcement failures."""


class SandboxUnavailableError(SandboxError):
    """Raised when mandatory enforcement cannot be established."""


class SandboxConfigurationError(SandboxError):
    """Raised when a caller requests an unsafe or malformed capability."""


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _overlaps(left: Path, right: Path) -> bool:
    return _is_within(left, right) or _is_within(right, left)


@lru_cache(maxsize=32)
def _dynamic_libraries(executable: str) -> tuple[str, ...]:
    """Resolve the exact shared objects needed by a trusted tool executable."""

    ldd = shutil.which("ldd")
    if not ldd:
        return ()
    try:
        completed = subprocess.run(
            [ldd, executable],
            capture_output=True,
            text=True,
            timeout=5,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            start_new_session=True,
        )
    except (OSError, subprocess.SubprocessError):
        return ()
    # A statically linked executable returns nonzero with "not a dynamic
    # executable" and needs no library grant. Dynamic output names every
    # resolved object as an absolute path, including the ELF interpreter.
    found: set[str] = set()
    for raw in re.findall(r"(?:=>\s*)?(/[^\s(]+)", completed.stdout or ""):
        try:
            path = Path(raw).resolve(strict=True)
        except OSError:
            continue
        if path.is_file():
            found.add(str(path))
    return tuple(sorted(found))


def _existing_runtime_grants(executable: Path) -> list[dict[str, str]]:
    """Return the exact immutable runtime surface needed by one executable."""

    grants: list[dict[str, str]] = [
        {"path": str(executable), "access": "read", "type": "file"}
    ]
    for library in _dynamic_libraries(str(executable)):
        grants.append({"path": library, "access": "read", "type": "file"})
    directories = ("/etc/ssl/certs",)
    files = (
        "/etc/ca-certificates.conf",
        "/etc/hosts",
        "/etc/resolv.conf",
        "/etc/nsswitch.conf",
        "/etc/passwd",
        "/etc/group",
        "/etc/ld.so.cache",
        "/etc/localtime",
        "/dev/null",
        "/dev/urandom",
        "/dev/random",
    )
    for raw in directories:
        path = Path(raw)
        if path.is_dir():
            grants.append({"path": str(path), "access": "read", "type": "directory"})
    for raw in files:
        path = Path(raw)
        if path.exists():
            grants.append({"path": str(path), "access": "read", "type": "file"})
    return grants


class SandboxExecutor:
    """Run Syft or Grype under a fresh nono capability manifest."""

    def __init__(
        self,
        *,
        nono_bin: str = "nono",
        mode: str | None = None,
        network_mode: str | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self.nono_bin = nono_bin
        self.mode = (mode or os.environ.get("SUPPLYDRIFT_TOOL_SANDBOX", "auto")).lower()
        self.network_mode = (
            network_mode
            or os.environ.get("SUPPLYDRIFT_SANDBOX_NETWORK", "best-effort")
        ).lower()
        if self.mode not in _MODE_VALUES:
            raise SandboxConfigurationError(
                "SUPPLYDRIFT_TOOL_SANDBOX must be required, auto, or off"
            )
        if self.network_mode not in _NETWORK_MODE_VALUES:
            raise SandboxConfigurationError(
                "SUPPLYDRIFT_SANDBOX_NETWORK must be require or best-effort"
            )
        self.log = logger or logging.getLogger("supplydrift.sandbox")
        self._ready: bool | None = None
        self._nono_path: str | None = None
        self._proxy_supported: bool | None = None
        self._lock = threading.Lock()

    def _emit(self, level: int, **event: object) -> None:
        payload = {"event": "supplydrift_tool_sandbox", **event}
        self.log.log(
            level,
            json.dumps(payload, sort_keys=True, separators=(",", ":")),
            extra={"sandbox": payload},
        )

    @staticmethod
    def _base_environment(job_root: Path) -> dict[str, str]:
        workspace = job_root / "work"
        env = {key: value for key in _BASE_ENV if (value := os.environ.get(key))}
        env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
        env.update(
            {
                # nono's own state stays outside the child-visible workspace.
                "HOME": str(job_root / "nono-home"),
                "TMPDIR": str(workspace / "tmp"),
                "XDG_CACHE_HOME": str(workspace / "cache"),
                # nono protects its own config/state roots from sandbox grants,
                # so keep them outside the child-writable workspace.
                "XDG_CONFIG_HOME": str(job_root / "nono-config"),
                "XDG_STATE_HOME": str(job_root / "nono-state"),
                "PYTHONDONTWRITEBYTECODE": "1",
                "NO_COLOR": "1",
            }
        )
        return env

    @staticmethod
    def _prepare_job_root(job_root: Path) -> None:
        (job_root / "nono-home").mkdir(mode=0o700)
        (job_root / "nono-config").mkdir(mode=0o700)
        (job_root / "nono-state").mkdir(mode=0o700)
        workspace = job_root / "work"
        workspace.mkdir(mode=0o700)
        for name in ("home", "tmp", "cache", "config", "state"):
            (workspace / name).mkdir(mode=0o700)

    @staticmethod
    def _child_environment_assignments(job_root: Path) -> list[str]:
        workspace = job_root / "work"
        return [
            f"HOME={workspace / 'home'}",
            f"TMPDIR={workspace / 'tmp'}",
            f"XDG_CACHE_HOME={workspace / 'cache'}",
            f"XDG_CONFIG_HOME={workspace / 'config'}",
            f"XDG_STATE_HOME={workspace / 'state'}",
        ]

    @staticmethod
    def _resolve_executable(value: str) -> Path:
        if not value or value.startswith("-"):
            raise SandboxConfigurationError("tool executable must not be empty or an option")
        found = shutil.which(value)
        if found is None:
            raise FileNotFoundError(value)
        resolved = Path(found).resolve(strict=True)
        if not resolved.is_file() or not os.access(resolved, os.X_OK):
            raise SandboxConfigurationError(f"tool executable is not executable: {resolved}")
        return resolved

    @staticmethod
    def _normalize_path(
        raw: str | os.PathLike[str],
        *,
        write: bool,
        allow_grype_db: bool,
    ) -> tuple[Path, str]:
        path = Path(raw).expanduser().resolve(strict=True)
        if path == Path("/"):
            raise SandboxConfigurationError("refusing to grant the filesystem root")
        forbidden = _WRITE_FORBIDDEN if write else _READ_FORBIDDEN
        if any(_overlaps(path, item) for item in forbidden):
            raise SandboxConfigurationError(f"refusing protected path grant: {path}")
        grype_db = Path("/opt/grype-db")
        if _overlaps(path, grype_db):
            if not allow_grype_db or not _is_within(path, grype_db):
                raise SandboxConfigurationError(
                    "only Grype may read the exact vulnerability database path"
                )
        return path, "directory" if path.is_dir() else "file"

    @staticmethod
    def _parse_nono_version(output: str) -> str | None:
        match = _NONO_VERSION_RE.fullmatch((output or "").strip())
        return match.group(1) if match else None

    @staticmethod
    def _proxy_domains(hostname: str) -> list[str]:
        """Return target-scoped auxiliary hosts required by major registries."""

        if hostname in {"docker.io", "index.docker.io", "registry-1.docker.io"}:
            return [
                "registry-1.docker.io",
                "auth.docker.io",
                "production.cloudflare.docker.com",
            ]
        if hostname == "ghcr.io":
            return ["ghcr.io", "pkg-containers.githubusercontent.com"]
        if hostname == "quay.io":
            return ["quay.io", "cdn.quay.io"]
        ecr = re.fullmatch(
            r"[0-9]+\.dkr\.ecr(?:-fips)?\.([a-z0-9-]+)\.(amazonaws\.com(?:\.cn)?)",
            hostname,
        )
        if ecr:
            region, suffix = ecr.groups()
            return [
                hostname,
                f"prod-{region}-starport-layer-bucket.s3.{region}.{suffix}",
            ]
        return [hostname]

    @staticmethod
    def _redact_output(value: str | None, environment: Mapping[str, str]) -> str:
        """Remove exact child credential values before output leaves the boundary."""

        output = value or ""
        variants: set[str] = set()
        for key in _SECRET_ENV:
            secret = environment.get(key, "")
            if not secret:
                continue
            variants.add(secret)
            variants.add(json.dumps(secret, ensure_ascii=True)[1:-1])
            variants.add(json.dumps(secret, ensure_ascii=False)[1:-1])
        for secret in sorted(variants, key=len, reverse=True):
            if secret:
                output = output.replace(secret, "[REDACTED]")
        return output

    @staticmethod
    def _validated_host(raw: str | None) -> tuple[str, str]:
        value = (raw or "").strip().lower().rstrip(".")
        if not value or any(ch.isspace() for ch in value) or any(ch in value for ch in "/@?#"):
            raise SandboxConfigurationError("proxy network policy requires a plain registry host")
        parsed = urlsplit(f"//{value}")
        try:
            port = parsed.port
        except ValueError as exc:
            raise SandboxConfigurationError("invalid registry port") from exc
        if not parsed.hostname or parsed.username or parsed.password:
            raise SandboxConfigurationError("invalid registry host")
        hostname = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        if not hostname or "*" in hostname:
            raise SandboxConfigurationError("wildcards are not valid registry hosts")
        endpoint = f"[{hostname}]:{port}" if ":" in hostname and port else hostname
        if port and ":" not in hostname:
            endpoint = f"{hostname}:{port}"
        return hostname, endpoint

    @staticmethod
    def _popen_capture(
        argv: Sequence[str],
        *,
        env: Mapping[str, str],
        timeout: int | float,
        cwd: str | os.PathLike[str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        reaper = Path(__file__).with_name("_reaper.py")
        fd, status_path = tempfile.mkstemp(prefix="supplydrift-reaper-", dir="/tmp")
        os.close(fd)
        helper = [
            sys.executable,
            "-I",
            "-S",
            str(reaper),
            "--status",
            status_path,
            "--timeout",
            str(timeout),
            "--",
            *list(argv),
        ]
        proc = subprocess.Popen(
            helper,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=dict(env),
            cwd=cwd,
            start_new_session=True,
        )
        try:
            try:
                stdout, stderr = proc.communicate(timeout=timeout + 15)
            except subprocess.TimeoutExpired as exc:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    stdout, stderr = proc.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    if proc.stdout:
                        proc.stdout.close()
                    if proc.stderr:
                        proc.stderr.close()
                    proc.wait(timeout=2)
                    stdout, stderr = "", "sandbox reaper did not terminate"
                exc.output = stdout
                exc.stderr = stderr
                raise
            try:
                status = json.loads(Path(status_path).read_text(encoding="utf-8") or "{}")
            except (OSError, json.JSONDecodeError):
                status = {}
            if status.get("timed_out"):
                raise subprocess.TimeoutExpired(
                    list(argv), timeout, output=stdout, stderr=stderr
                )
            returncode = int(status.get("returncode", proc.returncode or 125))
            if status.get("error"):
                stderr = f"{stderr}\nsandbox reaper: {status['error']}".strip()
            return subprocess.CompletedProcess(list(argv), returncode, stdout, stderr)
        finally:
            try:
                os.unlink(status_path)
            except OSError:
                pass

    def _run_check(
        self,
        argv: Sequence[str],
        env: Mapping[str, str],
        timeout: int,
        *,
        cwd: str | os.PathLike[str] | None = None,
    ) -> None:
        try:
            completed = self._popen_capture(argv, env=env, timeout=timeout, cwd=cwd)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SandboxUnavailableError(f"sandbox preflight failed: {exc}") from exc
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "unknown error").strip()[:500]
            raise SandboxUnavailableError(f"sandbox preflight failed: {detail}")

    def _filesystem_canary(self, nono_path: str, job_root: Path) -> None:
        shell = self._resolve_executable("/bin/sh")
        allowed = job_root / "allowed"
        output = job_root / "output"
        protected = job_root / "protected"
        denied_root = Path(tempfile.mkdtemp(prefix="supplydrift-sandbox-denied-"))
        denied = denied_root / "secret"
        try:
            allowed.write_text("allowed\n", encoding="utf-8")
            output.write_text("", encoding="utf-8")
            protected.write_text("protected\n", encoding="utf-8")
            denied.write_text("secret\n", encoding="utf-8")
            protected.chmod(0o644)
            grants = _existing_runtime_grants(shell)
            grants.extend(
                [
                    {"path": str(allowed), "access": "read", "type": "file"},
                    {"path": str(output), "access": "readwrite", "type": "file"},
                    {"path": str(protected), "access": "read", "type": "file"},
                ]
            )
            manifest = {
                "version": "0.1.0",
                "filesystem": {"grants": grants},
                "network": {"mode": "blocked"},
                "process": {"exec_strategy": "direct"},
            }
            manifest_path = job_root / "canary-manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            manifest_path.chmod(0o600)
            script = (
                'IFS= read -r value < "$1" || exit 10; '
                '[ "$value" = allowed ] || exit 11; '
                'if IFS= read -r leaked < "$2"; then exit 12; fi; '
                'printf passed > "$3" || exit 13; '
                'if printf escaped > "$4"; then exit 14; fi; '
                '[ -z "${SUPPLYDRIFT_RUNNER_TOKEN+x}" ] || exit 15; '
                '[ -z "${SUPPLYDRIFT_SECRET_KEY+x}" ] || exit 16; '
                '[ -z "${AWS_ACCESS_KEY_ID+x}" ] || exit 17; '
                '[ -z "${KUBECONFIG+x}" ] || exit 18; '
                '[ -z "${DOCKER_CONFIG+x}" ] || exit 19; '
                # A parser must not recover the publisher token from its parent
                # process even when the token was file-loaded rather than exported.
                'if IFS= read -r parent_env < "$5"; then exit 20; fi'
            )
            env = self._base_environment(job_root)
            command = [
                nono_path,
                "--silent",
                "wrap",
                "--no-diagnostics",
                "--config",
                str(manifest_path),
                "--",
                str(shell),
                "-c",
                script,
                "supplydrift-canary",
                str(allowed),
                str(denied),
                str(output),
                str(protected),
                f"/proc/{os.getpid()}/environ",
            ]
            self._run_check(command, env, 20, cwd=job_root)
            if output.read_text(encoding="utf-8") != "passed":
                raise SandboxUnavailableError("filesystem canary did not write its allowed output")
            if protected.read_text(encoding="utf-8") != "protected\n":
                raise SandboxUnavailableError("filesystem canary modified a read-only input")
        finally:
            shutil.rmtree(denied_root, ignore_errors=True)

    def _blocked_network_canary(self, nono_path: str, job_root: Path) -> None:
        """Prove that block-all denies a TCP socket before claiming enforcement."""

        python = Path(os.path.realpath(os.sys.executable))
        if not python.is_file():
            raise SandboxUnavailableError("network canary could not resolve Python")
        grants = _existing_runtime_grants(python)
        # The canary is trusted bootstrap code.  Python needs only its immutable
        # standard library and libpython; scanner application paths remain absent.
        for raw in (
            Path(os.__file__).resolve().parent,
            Path("/usr/local/lib"),
        ):
            if raw.is_dir() and not any(item["path"] == str(raw) for item in grants):
                grants.append({"path": str(raw), "access": "read", "type": "directory"})
        grants.append(
            {
                "path": str(job_root / "work"),
                "access": "readwrite",
                "type": "directory",
            }
        )
        manifest = {
            "version": "0.1.0",
            "filesystem": {"grants": grants},
            "network": {"mode": "blocked"},
            "process": {"exec_strategy": "direct"},
        }
        manifest_path = job_root / "network-canary-manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        manifest_path.chmod(0o600)
        script = (
            "import socket,sys; "
            "s=None; "
            "\ntry:\n s=socket.socket(); s.bind(('127.0.0.1', 0))"
            "\nexcept PermissionError:\n sys.exit(0)"
            "\nexcept OSError as exc:\n sys.exit(0 if exc.errno in (1, 13) else 22)"
            "\nsys.exit(21)"
        )
        command = [
            nono_path,
            "--silent",
            "wrap",
            "--no-diagnostics",
            "--config",
            str(manifest_path),
            "--",
            str(python),
            "-I",
            "-S",
            "-c",
            script,
        ]
        self._run_check(
            command,
            self._base_environment(job_root),
            20,
            cwd=job_root / "work",
        )

    def ensure_ready(self) -> bool:
        """Verify the pinned runtime and filesystem enforcement once per process."""

        with self._lock:
            if self._ready is not None:
                return self._ready
            if self.mode == "off":
                self._ready = False
                self._emit(
                    logging.WARNING,
                    enforcement="off",
                    filesystem_enforced=False,
                    network_enforced=False,
                    reason="development override",
                )
                return False
            found = shutil.which(self.nono_bin)
            if found is None:
                if self.mode == "required":
                    raise SandboxUnavailableError(
                        f"required sandbox executable '{self.nono_bin}' was not found"
                    )
                self._ready = False
                self._emit(
                    logging.WARNING,
                    enforcement="auto",
                    filesystem_enforced=False,
                    network_enforced=False,
                    reason="nono not installed; local development fallback",
                )
                return False
            nono_path = str(Path(found).resolve(strict=True))
            try:
                with tempfile.TemporaryDirectory(prefix="supplydrift-sandbox-preflight-") as raw:
                    job_root = Path(raw)
                    self._prepare_job_root(job_root)
                    env = self._base_environment(job_root)
                    version = self._popen_capture(
                        [nono_path, "--version"], env=env, timeout=10, cwd=job_root
                    )
                    parsed_version = self._parse_nono_version(version.stdout)
                    if version.returncode != 0 or parsed_version != EXPECTED_NONO_VERSION:
                        got = (version.stdout or version.stderr or "unknown").strip()[:100]
                        raise SandboxUnavailableError(
                            f"nono {EXPECTED_NONO_VERSION} is required; found {got}"
                        )
                    self._run_check(
                        [nono_path, "setup", "--check-only"], env, 30, cwd=job_root
                    )
                    self._filesystem_canary(nono_path, job_root)
                    self._blocked_network_canary(nono_path, job_root)
            except (OSError, SandboxUnavailableError, subprocess.TimeoutExpired) as exc:
                if self.mode == "required":
                    if isinstance(exc, SandboxUnavailableError):
                        raise
                    raise SandboxUnavailableError(str(exc)) from exc
                self._ready = False
                self._emit(
                    logging.WARNING,
                    enforcement="auto",
                    filesystem_enforced=False,
                    network_enforced=False,
                    reason=f"sandbox preflight failed: {exc}",
                )
                return False
            self._nono_path = nono_path
            self._ready = True
            self._emit(
                logging.INFO,
                enforcement=self.mode,
                filesystem_enforced=True,
                network_enforced=None,
                nono_version=EXPECTED_NONO_VERSION,
            )
            return True

    def _proxy_preflight(self, allowed_host: str) -> bool:
        if self._proxy_supported is not None:
            return self._proxy_supported
        assert self._nono_path is not None
        hostname, endpoint = self._validated_host(allowed_host)
        try:
            with tempfile.TemporaryDirectory(prefix="supplydrift-sandbox-proxy-") as raw:
                root = Path(raw)
                self._prepare_job_root(root)
                true_bin = self._resolve_executable("true")
                manifest = {
                    "version": "0.1.0",
                    "filesystem": {
                        "grants": [
                            *_existing_runtime_grants(true_bin),
                            {
                                "path": str(root / "work"),
                                "access": "readwrite",
                                "type": "directory",
                            },
                        ]
                    },
                    "network": {
                        "mode": "proxy",
                        "allow_domains": self._proxy_domains(hostname),
                        "endpoints": [{"host": endpoint}],
                    },
                    "process": {"exec_strategy": "supervised"},
                }
                config = root / "proxy-manifest.json"
                config.write_text(json.dumps(manifest), encoding="utf-8")
                config.chmod(0o600)
                completed = self._popen_capture(
                    [
                        self._nono_path,
                        "--silent",
                        "run",
                        "--no-audit",
                        "--no-diagnostics",
                        "--config",
                        str(config),
                        "--",
                        str(true_bin),
                    ],
                    env=self._base_environment(root),
                    timeout=20,
                    cwd=root / "work",
                )
                self._proxy_supported = completed.returncode == 0
        except (OSError, subprocess.TimeoutExpired, SandboxConfigurationError):
            self._proxy_supported = False
        return self._proxy_supported

    def _manifest(
        self,
        *,
        executable: Path,
        tool: str,
        job_root: Path,
        read_paths: Iterable[str | os.PathLike[str]],
        write_paths: Iterable[str | os.PathLike[str]],
        network_policy: NetworkPolicy,
        allowed_host: str | None,
        launcher: Path | None = None,
    ) -> dict[str, object]:
        grants = _existing_runtime_grants(executable)
        if launcher is not None:
            for grant in _existing_runtime_grants(launcher):
                if grant not in grants:
                    grants.append(grant)
        grants.append(
            {
                "path": str(job_root / "work"),
                "access": "readwrite",
                "type": "directory",
            }
        )
        seen = {(g["path"], g["access"]) for g in grants}
        for raw in read_paths:
            path, kind = self._normalize_path(raw, write=False, allow_grype_db=tool == "grype")
            item = (str(path), "read")
            if item not in seen:
                grants.append({"path": item[0], "access": item[1], "type": kind})
                seen.add(item)
        for raw in write_paths:
            path, kind = self._normalize_path(raw, write=True, allow_grype_db=False)
            # Writable outputs are deliberately read/write: tools commonly create,
            # reopen, and atomically replace their own temporary output.
            item = (str(path), "readwrite")
            if item not in seen:
                grants.append({"path": item[0], "access": item[1], "type": kind})
                seen.add(item)
        network: dict[str, object] = {"mode": network_policy.value}
        if network_policy is NetworkPolicy.PROXY:
            hostname, endpoint = self._validated_host(allowed_host)
            network.update(
                {
                    "allow_domains": self._proxy_domains(hostname),
                    "endpoints": [{"host": endpoint}],
                }
            )
        return {
            "version": "0.1.0",
            "filesystem": {"grants": grants},
            "network": network,
            "process": {
                "ipc_mode": "shared_memory_only",
                "exec_strategy": (
                    "supervised" if network_policy is NetworkPolicy.PROXY else "direct"
                ),
            },
        }

    def run(
        self,
        tool: str,
        argv: Sequence[str],
        read_paths: Iterable[str | os.PathLike[str]] = (),
        write_paths: Iterable[str | os.PathLike[str]] = (),
        environment: Mapping[str, str] | None = None,
        network_policy: NetworkPolicy | str = NetworkPolicy.BLOCKED,
        allowed_host: str | None = None,
        timeout_seconds: int | float = 600,
    ) -> subprocess.CompletedProcess[str]:
        """Execute one cataloguer with an exact, ephemeral capability set."""

        if tool not in _TOOL_ENV or not _SAFE_TOOL_NAME.fullmatch(tool):
            raise SandboxConfigurationError("only the syft and grype tools are supported")
        if not argv:
            raise SandboxConfigurationError("tool argv must not be empty")
        if timeout_seconds <= 0:
            raise SandboxConfigurationError("tool timeout must be positive")
        executable = self._resolve_executable(str(argv[0]))
        command = [str(executable), *(str(value) for value in argv[1:])]
        extras = dict(environment or {})
        unexpected = sorted(set(extras) - _TOOL_ENV[tool])
        if unexpected:
            raise SandboxConfigurationError(
                f"environment variable(s) not allowed for {tool}: {', '.join(unexpected)}"
            )
        try:
            requested_network = NetworkPolicy(network_policy)
        except ValueError as exc:
            raise SandboxConfigurationError(f"invalid network policy: {network_policy}") from exc
        if requested_network is NetworkPolicy.PROXY:
            self._validated_host(allowed_host)

        enforced = self.ensure_ready()
        with tempfile.TemporaryDirectory(prefix=f"supplydrift-{tool}-") as raw:
            job_root = Path(raw)
            self._prepare_job_root(job_root)
            env = self._base_environment(job_root)
            env.update(extras)
            child_assignments = self._child_environment_assignments(job_root)
            effective_network = requested_network
            network_enforced = requested_network is NetworkPolicy.BLOCKED and enforced
            fallback_reason = ""
            if requested_network is NetworkPolicy.PROXY and enforced:
                if self._proxy_preflight(allowed_host or ""):
                    network_enforced = True
                elif self.network_mode == "require":
                    raise SandboxUnavailableError(
                        "registry-host network proxy is required but unavailable"
                    )
                else:
                    effective_network = NetworkPolicy.UNRESTRICTED
                    fallback_reason = "registry-host proxy unavailable"
            elif requested_network is NetworkPolicy.PROXY:
                network_enforced = False
                fallback_reason = "tool sandbox unavailable"

            if not enforced:
                for assignment in child_assignments:
                    key, value = assignment.split("=", 1)
                    env[key] = value
                self._emit(
                    logging.WARNING,
                    tool=tool,
                    filesystem_enforced=False,
                    network_enforced=False,
                    network_mode="unrestricted-local-fallback",
                    target_host=allowed_host,
                    reason=fallback_reason or "local development mode",
                )
                completed = self._popen_capture(
                    command, env=env, timeout=timeout_seconds, cwd=job_root / "work"
                )
                return subprocess.CompletedProcess(
                    command,
                    completed.returncode,
                    self._redact_output(completed.stdout, extras),
                    self._redact_output(completed.stderr, extras),
                )

            launcher = self._resolve_executable("env")
            manifest = self._manifest(
                executable=executable,
                tool=tool,
                job_root=job_root,
                read_paths=read_paths,
                write_paths=write_paths,
                network_policy=effective_network,
                allowed_host=allowed_host,
                launcher=launcher,
            )
            manifest_path = job_root / "capabilities.json"
            manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
            manifest_path.chmod(0o600)
            launched_command = [str(launcher), *child_assignments, *command]
            if effective_network is NetworkPolicy.PROXY:
                wrapped = [
                    self._nono_path or self.nono_bin,
                    "--silent",
                    "run",
                    "--no-audit",
                    "--no-diagnostics",
                    "--config",
                    str(manifest_path),
                    "--",
                    *launched_command,
                ]
            else:
                # Direct exec leaves no unsandboxed supervisor process beside
                # the hostile parser. Block-all egress is installed before exec.
                wrapped = [
                    self._nono_path or self.nono_bin,
                    "--silent",
                    "wrap",
                    "--no-diagnostics",
                    "--config",
                    str(manifest_path),
                    "--",
                    *launched_command,
                ]
            self._emit(
                logging.WARNING if fallback_reason else logging.INFO,
                tool=tool,
                filesystem_enforced=True,
                network_enforced=network_enforced,
                network_mode=(
                    "unrestricted-fallback" if fallback_reason else effective_network.value
                ),
                target_host=allowed_host,
                reason=fallback_reason or None,
            )
            completed = self._popen_capture(
                wrapped, env=env, timeout=timeout_seconds, cwd=job_root / "work"
            )
            return subprocess.CompletedProcess(
                command,
                completed.returncode,
                self._redact_output(completed.stdout, extras),
                self._redact_output(completed.stderr, extras),
            )
