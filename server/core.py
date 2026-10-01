from __future__ import annotations

import json
import hashlib
import hmac
import os
import re
import subprocess
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


ALIAS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SERVICE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}$")
TARGET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SAFE_PATH_RE = re.compile(r"^/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+$")
ENVIRONMENTS = {"development", "staging", "production"}
CONNECTION_MODES = {"managed", "ssh-config-alias"}
SECRET_PATTERNS = [
    re.compile(r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key)\b\s*[:=]\s*([^\s,;]+)"),
    re.compile(r"(?i)\b([A-Z0-9_]*(?:PASSWORD|PASSWD|TOKEN|SECRET|API_KEY)[A-Z0-9_]*)\b\s*[:=]\s*([^\s,;]+)"),
    re.compile(r"(?i)\b(authorization)\b\s*:\s*(?:bearer|basic)\s+[^\s]+"),
    re.compile(r"(?i)(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s]+"),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.S),
]


class SrmError(Exception):
    """Safe, user-facing error."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def redact(value: str) -> str:
    text = value
    text = SECRET_PATTERNS[0].sub(lambda m: f"{m.group(1)}=[REDACTED]", text)
    text = SECRET_PATTERNS[1].sub(lambda m: f"{m.group(1)}=[REDACTED]", text)
    text = SECRET_PATTERNS[2].sub(lambda m: f"{m.group(1)}: [REDACTED]", text)
    text = SECRET_PATTERNS[3].sub("[REDACTED_CONNECTION_STRING]", text)
    text = SECRET_PATTERNS[4].sub("[REDACTED_PRIVATE_KEY]", text)
    return text


def sanitize_error(value: str) -> str:
    """Redact secrets and local filesystem paths from agent-visible errors."""
    text = redact(value)
    text = re.sub(r"(?i)(?:[A-Z]:\\|\\\\)[^\r\n\"']+", "[path]", text)
    text = re.sub(r"(?i)(?<![A-Za-z0-9])/(?:home|users|root|var|etc|opt|tmp)/[^\s\"']+", "[path]", text)
    return text


def _path_has_reparse_component(path: Path, root: Path) -> bool:
    current = path
    while current != root and current != current.parent:
        try:
            stat_result = current.lstat()
            if current.is_symlink() or bool(getattr(stat_result, "st_file_attributes", 0) & 0x400):
                return True
        except FileNotFoundError:
            pass
        current = current.parent
    return False


def _validate_alias(alias: Any) -> str:
    if not isinstance(alias, str) or not ALIAS_RE.fullmatch(alias):
        raise SrmError("Invalid profile alias.")
    return alias


def _validate_profile(profile: dict[str, Any]) -> dict[str, Any]:
    alias = _validate_alias(profile.get("alias"))
    if profile.get("environment") not in ENVIRONMENTS:
        raise SrmError(f"Profile '{alias}' has an invalid environment.")
    if not isinstance(profile.get("host"), str) or not profile["host"]:
        raise SrmError(f"Profile '{alias}' has an invalid host.")
    if not isinstance(profile.get("user"), str) or not profile["user"]:
        raise SrmError(f"Profile '{alias}' has an invalid user.")
    port = profile.get("port", 22)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise SrmError(f"Profile '{alias}' has an invalid port.")
    mode = profile.get("connectionMode", "managed")
    if mode not in CONNECTION_MODES:
        raise SrmError(f"Profile '{alias}' has an invalid connection mode.")
    if mode == "ssh-config-alias":
        _validate_alias(profile.get("sshConfigAlias"))
    return profile


class ProfileStore:
    def __init__(self, home: Path | None = None):
        configured = os.environ.get("SSH_REMOTE_MANAGER_HOME")
        self.home = Path(configured) if configured else (home or Path.home() / ".ssh" / "ssh-remote-manager")
        self.path = self.home / "profiles.json"

    def load(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise SrmError("Profile store is unavailable or invalid.") from exc
        if not isinstance(payload, dict) or payload.get("schemaVersion") != 1:
            raise SrmError("Unsupported profile store schema.")
        profiles = payload.get("profiles")
        if not isinstance(profiles, list):
            raise SrmError("Profile store is invalid.")
        seen: set[str] = set()
        validated: list[dict[str, Any]] = []
        for item in profiles:
            if not isinstance(item, dict):
                raise SrmError("Profile store is invalid.")
            profile = _validate_profile(item)
            folded = profile["alias"].casefold()
            if folded in seen:
                raise SrmError("Profile store contains a duplicate alias.")
            seen.add(folded)
            validated.append(profile)
        return validated

    def get(self, alias: Any) -> dict[str, Any]:
        wanted = _validate_alias(alias).casefold()
        for profile in self.load():
            if profile["alias"].casefold() == wanted:
                return profile
        raise SrmError("Unknown profile alias.")


class AuditLog:
    _lock = threading.Lock()
    ZERO_HASH = "0" * 64

    def __init__(self, home: Path, max_bytes: int = 2_000_000):
        self.path = home / "audit.jsonl"
        self.lock_path = home / "audit.lock"
        self.max_bytes = max_bytes

    @contextmanager
    def _process_lock(self, timeout_seconds: float = 5.0):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.lock_path.open("a+b")
        try:
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"\0")
                handle.flush()
            handle.seek(0)
            deadline = time.monotonic() + timeout_seconds
            while True:
                try:
                    if os.name == "nt":
                        import msvcrt
                        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except (OSError, BlockingIOError):
                    if time.monotonic() >= deadline:
                        raise SrmError("Timed out waiting for the audit lock.")
                    time.sleep(0.025)
            yield
        finally:
            try:
                handle.seek(0)
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
            handle.close()

    def _records_unlocked(self) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for path in (self.path.with_suffix(".jsonl.1"), self.path):
            if not path.exists():
                continue
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    value = json.loads(line)
                    if not isinstance(value, dict):
                        raise ValueError("audit record is not an object")
                    records.append(value)
        return records

    @classmethod
    def _record_hash(cls, entry: dict[str, Any]) -> str:
        canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def _archive_legacy_unlocked(self) -> None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        for index, path in enumerate((self.path.with_suffix(".jsonl.1"), self.path)):
            if path.exists():
                os.replace(path, self.path.with_name(f"audit.legacy.{stamp}.{index}.jsonl"))

    def append(self, *, tool: str, profile: dict[str, Any] | None, duration_ms: int,
               category: str, success: bool, agent: str = "mcp",
               request_id: str | None = None) -> None:
        with self._lock:
            with self._process_lock():
                records = self._records_unlocked()
                if records and ("hash" not in records[-1] or "sequence" not in records[-1]):
                    self._archive_legacy_unlocked()
                    records = []
                previous = records[-1] if records else None
                entry = {
                    "sequence": int(previous["sequence"]) + 1 if previous else 0,
                    "timestampUtc": utc_now(), "requestId": request_id or uuid.uuid4().hex,
                    "agent": agent, "tool": tool,
                    "profileAlias": profile.get("alias") if profile else None,
                    "environment": profile.get("environment") if profile else None,
                    "durationMs": max(0, int(duration_ms)), "exitCategory": category,
                    "success": bool(success), "prevHash": previous["hash"] if previous else self.ZERO_HASH,
                }
                entry["hash"] = self._record_hash(entry)
                line = json.dumps(entry, separators=(",", ":"), ensure_ascii=True) + "\n"
                if self.path.exists() and self.path.stat().st_size + len(line.encode("utf-8")) > self.max_bytes:
                    rotated = self.path.with_suffix(".jsonl.1")
                    os.replace(self.path, rotated)
                with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                    handle.write(line)
                    handle.flush()
                    os.fsync(handle.fileno())

    def recent(self, limit: int) -> list[dict[str, Any]]:
        try:
            with self._lock:
                with self._process_lock():
                    records = self._records_unlocked()[-limit:]
            allowed = {"sequence", "timestampUtc", "requestId", "agent", "tool", "profileAlias",
                       "environment", "durationMs", "exitCategory", "success"}
            return [{k: v for k, v in record.items() if k in allowed} for record in records]
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
            raise SrmError("Audit log is unavailable or invalid.") from exc

    def verify(self) -> dict[str, Any]:
        try:
            with self._lock:
                with self._process_lock():
                    records = self._records_unlocked()
            previous_hash: str | None = None
            previous_sequence: int | None = None
            for index, record in enumerate(records):
                supplied_hash = record.get("hash")
                sequence = record.get("sequence")
                if not isinstance(supplied_hash, str) or not isinstance(sequence, int):
                    return {"valid": False, "recordsChecked": index, "error": "legacy_or_invalid_record"}
                if previous_hash is not None and record.get("prevHash") != previous_hash:
                    return {"valid": False, "recordsChecked": index, "error": "broken_hash_link"}
                if previous_sequence is not None and sequence != previous_sequence + 1:
                    return {"valid": False, "recordsChecked": index, "error": "broken_sequence"}
                unsigned = {k: v for k, v in record.items() if k != "hash"}
                expected = self._record_hash(unsigned)
                if not hmac.compare_digest(supplied_hash, expected):
                    return {"valid": False, "recordsChecked": index, "error": "record_hash_mismatch"}
                previous_hash, previous_sequence = supplied_hash, sequence
            return {"valid": True, "recordsChecked": len(records),
                    "firstSequence": records[0]["sequence"] if records else None,
                    "lastSequence": records[-1]["sequence"] if records else None,
                    "lastHash": records[-1]["hash"] if records else self.ZERO_HASH}
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
            return {"valid": False, "recordsChecked": 0, "error": "audit_unreadable"}


@dataclass
class RunResult:
    status: str
    exit_code: int | None
    duration_ms: int
    stdout: str
    stderr: str
    truncated: bool


class SshRunner:
    def __init__(self, executable: str | list[str] | None = None, timeout_seconds: int = 10,
                 output_limit: int = 65536):
        configured = executable or os.environ.get("SSH_REMOTE_MANAGER_SSH", "ssh.exe")
        if isinstance(configured, list):
            self.command_prefix = configured
        elif configured.startswith("["):
            parsed = json.loads(configured)
            if not isinstance(parsed, list) or not parsed or not all(isinstance(v, str) and v for v in parsed):
                raise SrmError("Invalid SSH executable configuration.")
            self.command_prefix = parsed
        else:
            self.command_prefix = [configured]
        self.timeout_seconds = min(max(timeout_seconds, 1), 30)
        self.output_limit = min(max(output_limit, 1024), 262144)

    def run(self, alias: str, remote_args: Iterable[str], timeout: int | None = None) -> RunResult:
        _validate_alias(alias)
        args = [*self.command_prefix, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                "-o", f"ConnectTimeout={self.timeout_seconds}", "--", alias, *remote_args]
        started = time.monotonic()
        try:
            process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, shell=False)
        except (OSError, ValueError) as exc:
            raise SrmError("SSH client could not be started.") from exc

        buffers = [bytearray(), bytearray()]
        over = [False, False]

        def drain(stream: Any, index: int) -> None:
            while True:
                chunk = stream.read(4096)
                if not chunk:
                    break
                remaining = self.output_limit - len(buffers[index])
                if remaining > 0:
                    buffers[index].extend(chunk[:remaining])
                if len(chunk) > remaining:
                    over[index] = True

        threads = [threading.Thread(target=drain, args=(process.stdout, 0), daemon=True),
                   threading.Thread(target=drain, args=(process.stderr, 1), daemon=True)]
        for thread in threads:
            thread.start()
        timed_out = False
        try:
            process.wait(timeout=min(timeout or self.timeout_seconds, 30))
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            process.wait()
        for thread in threads:
            thread.join(timeout=2)
        process.stdout.close()
        process.stderr.close()
        duration_ms = round((time.monotonic() - started) * 1000)
        stdout = redact(buffers[0].decode("utf-8", errors="replace"))
        stderr = sanitize_error(buffers[1].decode("utf-8", errors="replace"))
        if timed_out:
            return RunResult("timeout", None, duration_ms, stdout, "SSH operation timed out.", any(over))
        status = "success" if process.returncode == 0 else classify_error(stderr)
        return RunResult(status, process.returncode, duration_ms, stdout, stderr, any(over))


def classify_error(stderr: str) -> str:
    lowered = stderr.lower()
    if "host key verification failed" in lowered:
        return "unknown_host"
    if "permission denied" in lowered:
        return "authentication_failed"
    if "could not resolve hostname" in lowered:
        return "dns_failed"
    if "connection timed out" in lowered or "connection refused" in lowered:
        return "unreachable"
    return "ssh_failed"


def public_profile(profile: dict[str, Any], key_ready: bool | None) -> dict[str, Any]:
    return {
        "alias": profile["alias"], "displayName": profile.get("displayName", profile["alias"]),
        "host": profile["host"], "port": profile.get("port", 22), "user": profile["user"],
        "environment": profile["environment"], "capabilities": profile.get("capabilities", {}),
        "allowlists": profile.get("allowlists", {}), "lastTestedUtc": profile.get("lastTestedUtc"),
        "keyReady": key_ready, "connectionMode": profile.get("connectionMode", "managed"),
        "authSource": "ssh-config" if profile.get("connectionMode") == "ssh-config-alias" else "managed-key",
    }


class SshRemoteService:
    def __init__(self, store: ProfileStore | None = None, runner: SshRunner | None = None):
        self.store = store or ProfileStore()
        self.runner = runner or SshRunner()
        self.audit = AuditLog(self.store.home)

    @staticmethod
    def _key_ready(profile: dict[str, Any]) -> bool | None:
        if profile.get("connectionMode") == "ssh-config-alias":
            return None
        path = profile.get("identityFile")
        if not isinstance(path, str) or not path:
            return False
        try:
            ssh_root = (Path.home() / ".ssh").absolute()
            candidate = Path(os.path.expandvars(path)).expanduser().absolute()
            if not candidate.is_relative_to(ssh_root) or _path_has_reparse_component(candidate, ssh_root):
                return False
            resolved_root = ssh_root.resolve(strict=False)
            resolved = candidate.resolve(strict=False)
            return resolved.is_relative_to(resolved_root) and resolved.is_file()
        except (OSError, RuntimeError):
            return False

    def list_profiles(self) -> list[dict[str, Any]]:
        return [{k: v for k, v in public_profile(p, self._key_ready(p)).items()
                 if k not in {"allowlists", "lastTestedUtc", "keyReady"}} for p in self.store.load()]

    def get_profile(self, alias: Any) -> dict[str, Any]:
        profile = self.store.get(alias)
        return public_profile(profile, self._key_ready(profile))

    def _run(self, tool: str, profile: dict[str, Any], args: list[str]) -> RunResult:
        target = profile.get("sshConfigAlias") if profile.get("connectionMode") == "ssh-config-alias" else profile["alias"]
        return self.runner.run(target, args)

    @staticmethod
    def _result(result: RunResult) -> dict[str, Any]:
        return {"status": result.status, "success": result.status == "success",
                "durationMs": result.duration_ms, "exitCode": result.exit_code,
                "output": result.stdout, "error": result.stderr, "truncated": result.truncated}

    def test_connection(self, alias: Any) -> dict[str, Any]:
        profile = self.store.get(alias)
        result = self._run("ssh_test_connection", profile, ["true"])
        payload = self._result(result)
        payload["latencyMs"] = result.duration_ms
        payload.pop("output", None)
        return payload

    def server_info(self, alias: Any) -> dict[str, Any]:
        profile = self.store.get(alias)
        if not profile.get("capabilities", {}).get("serverInfo", True):
            raise SrmError("Server information is disabled by profile policy.")
        command = ["sh", "-c", "printf 'hostname='; hostname; printf 'os='; uname -srm; "
                   "printf 'uptime='; uptime; printf 'memory='; (free -h 2>/dev/null || true); "
                   "printf 'cpu_count='; (nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || true); "
                   "printf 'disk='; df -h / 2>/dev/null"]
        return self._result(self._run("ssh_get_server_info", profile, command))

    def service_status(self, alias: Any, service: Any, kind: Any = "systemd") -> dict[str, Any]:
        profile = self.store.get(alias)
        if not isinstance(service, str) or not SERVICE_RE.fullmatch(service):
            raise SrmError("Invalid service name.")
        allowed = profile.get("allowlists", {}).get("services", [])
        if service not in allowed:
            raise SrmError("Service is not in this profile's allowlist.")
        capabilities = profile.get("capabilities", {})
        if kind == "systemd" and capabilities.get("systemd", False):
            args = ["systemctl", "show", "--no-pager", "--property=ActiveState,SubState,LoadState", "--", service]
        elif kind == "docker" and capabilities.get("docker", False):
            args = ["docker", "inspect", "--format={{.State.Status}}", "--", service]
        else:
            raise SrmError("Requested service provider is disabled by profile policy.")
        return self._result(self._run("ssh_service_status", profile, args))

    def read_logs(self, alias: Any, target: Any, lines: Any = 100) -> dict[str, Any]:
        profile = self.store.get(alias)
        if not profile.get("capabilities", {}).get("logs", False):
            raise SrmError("Log access is disabled by profile policy.")
        if not isinstance(target, str) or not TARGET_RE.fullmatch(target):
            raise SrmError("Invalid log target.")
        if isinstance(lines, bool) or not isinstance(lines, int) or not 1 <= lines <= 500:
            raise SrmError("lines must be an integer from 1 to 500.")
        targets = profile.get("allowlists", {}).get("logTargets", [])
        if isinstance(targets, dict):
            path = targets.get(target)
        elif isinstance(targets, list):
            path = next((item.get("path") for item in targets
                         if isinstance(item, dict) and item.get("name") == target), None)
        else:
            path = None
        if not isinstance(path, str) or not SAFE_PATH_RE.fullmatch(path):
            raise SrmError("Log target is not in this profile's safe allowlist.")
        return self._result(self._run("ssh_read_logs", profile, ["tail", "-n", str(lines), "--", path]))

    def audit_recent(self, limit: Any = 20) -> list[dict[str, Any]]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise SrmError("limit must be an integer from 1 to 100.")
        return self.audit.recent(limit)

    def audit_verify(self) -> dict[str, Any]:
        return self.audit.verify()
