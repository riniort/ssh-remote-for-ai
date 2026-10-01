#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from server.core import SrmError, SshRemoteService


TOOLS = [
    {
        "name": "ssh_list_profiles",
        "description": "List configured SSH profile metadata. Never returns key paths or key content.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "ssh_get_profile",
        "description": "Get metadata, environment and read-only policy for one profile alias.",
        "inputSchema": {"type": "object", "properties": {"alias": {"type": "string"}},
                        "required": ["alias"], "additionalProperties": False},
    },
    {
        "name": "ssh_test_connection",
        "description": "Test a configured profile using BatchMode and strict host-key verification.",
        "inputSchema": {"type": "object", "properties": {"alias": {"type": "string"}},
                        "required": ["alias"], "additionalProperties": False},
    },
    {
        "name": "ssh_get_server_info",
        "description": "Read hostname, OS, uptime, memory and root disk information with a fixed command.",
        "inputSchema": {"type": "object", "properties": {"alias": {"type": "string"}},
                        "required": ["alias"], "additionalProperties": False},
    },
    {
        "name": "ssh_service_status",
        "description": "Read status for a systemd or Docker service explicitly allowlisted by the profile.",
        "inputSchema": {"type": "object", "properties": {
            "alias": {"type": "string"}, "service": {"type": "string"},
            "kind": {"type": "string", "enum": ["systemd", "docker"], "default": "systemd"}},
            "required": ["alias", "service"], "additionalProperties": False},
    },
    {
        "name": "ssh_read_logs",
        "description": "Read bounded tail output from a named log target explicitly allowlisted by the profile.",
        "inputSchema": {"type": "object", "properties": {
            "alias": {"type": "string"}, "target": {"type": "string"},
            "lines": {"type": "integer", "minimum": 1, "maximum": 500, "default": 100}},
            "required": ["alias", "target"], "additionalProperties": False},
    },
    {
        "name": "ssh_audit_recent",
        "description": "Read sanitized local audit metadata. Command output and secrets are never recorded.",
        "inputSchema": {"type": "object", "properties": {
            "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20}},
            "additionalProperties": False},
    },
    {
        "name": "ssh_audit_verify",
        "description": "Verify the local audit sequence and SHA-256 hash chain without returning command output.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
]


def dispatch(service: SshRemoteService, name: str, arguments: dict[str, Any]) -> Any:
    if not isinstance(arguments, dict):
        raise SrmError("Tool arguments must be an object.")
    if name == "ssh_list_profiles":
        return service.list_profiles()
    if name == "ssh_get_profile":
        return service.get_profile(arguments.get("alias"))
    if name == "ssh_test_connection":
        return service.test_connection(arguments.get("alias"))
    if name == "ssh_get_server_info":
        return service.server_info(arguments.get("alias"))
    if name == "ssh_service_status":
        return service.service_status(arguments.get("alias"), arguments.get("service"),
                                      arguments.get("kind", "systemd"))
    if name == "ssh_read_logs":
        return service.read_logs(arguments.get("alias"), arguments.get("target"),
                                 arguments.get("lines", 100))
    if name == "ssh_audit_recent":
        return service.audit_recent(arguments.get("limit", 20))
    if name == "ssh_audit_verify":
        return service.audit_verify()
    raise SrmError("Unknown tool.")


def _content(payload: Any, is_error: bool = False) -> dict[str, Any]:
    result = {"content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False)}]}
    if is_error:
        result["isError"] = True
    else:
        result["structuredContent"] = {"result": payload}
    return result


def handle(service: SshRemoteService, request: dict[str, Any]) -> dict[str, Any] | None:
    method = request.get("method")
    request_id = request.get("id")
    if request_id is None:
        return None
    try:
        if method == "initialize":
            result = {"protocolVersion": request.get("params", {}).get("protocolVersion", "2025-03-26"),
                      "capabilities": {"tools": {"listChanged": False}},
                      "serverInfo": {"name": "ssh-remote-manager", "version": "0.1.0"}}
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            params = request.get("params") or {}
            tool = params.get("name")
            arguments = params.get("arguments") or {}
            started = time.monotonic()
            profile = None
            category, success = "internal_error", False
            try:
                if isinstance(arguments, dict) and isinstance(arguments.get("alias"), str):
                    profile = service.store.get(arguments["alias"])
                payload = dispatch(service, tool, arguments)
                result = _content(payload)
                category, success = "success", True
            except SrmError as exc:
                result = _content({"error": str(exc)}, True)
                category, success = "policy_or_input_error", False
            finally:
                if tool not in {"ssh_audit_recent", "ssh_audit_verify"}:
                    service.audit.append(tool=str(tool), profile=profile,
                                         duration_ms=round((time.monotonic() - started) * 1000),
                                         category=category, success=success)
        else:
            return {"jsonrpc": "2.0", "id": request_id,
                    "error": {"code": -32601, "message": "Method not found"}}
        return {"jsonrpc": "2.0", "id": request_id, "result": result}
    except SrmError as exc:
        return {"jsonrpc": "2.0", "id": request_id,
                "error": {"code": -32000, "message": str(exc)}}
    except Exception:
        return {"jsonrpc": "2.0", "id": request_id,
                "error": {"code": -32603, "message": "Internal server error"}}


def read_message(stream: Any) -> dict[str, Any] | None:
    line = stream.readline()
    if not line:
        return None
    if line.lower().startswith(b"content-length:"):
        length = int(line.split(b":", 1)[1].strip())
        while True:
            header = stream.readline()
            if header in {b"\r\n", b"\n", b""}:
                break
        raw = stream.read(length)
    else:
        raw = line
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Request must be an object")
    return value


def main() -> int:
    service = SshRemoteService()
    while True:
        try:
            request = read_message(sys.stdin.buffer)
            if request is None:
                return 0
            response = handle(service, request)
            if response is not None:
                sys.stdout.write(json.dumps(response, separators=(",", ":"), ensure_ascii=False) + "\n")
                sys.stdout.flush()
        except (ValueError, UnicodeError, json.JSONDecodeError):
            response = {"jsonrpc": "2.0", "id": None,
                        "error": {"code": -32700, "message": "Parse error"}}
            sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    raise SystemExit(main())
