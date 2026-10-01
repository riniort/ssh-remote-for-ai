from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class McpProtocolTests(unittest.TestCase):
    def test_all_phase_one_tools_smoke_without_secret_leakage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            secret = "DO_NOT_LEAK_PRIVATE_KEY_PATH"
            profile = {"schemaVersion": 1, "profiles": [{
                "alias": "dev-one", "displayName": "Dev", "host": "dev.example.test",
                "port": 22, "user": "deploy", "environment": "development",
                "identityFile": str(home / secret),
                "capabilities": {"serverInfo": True, "systemd": True, "docker": True, "logs": True},
                "allowlists": {"services": ["api"],
                               "logTargets": [{"name": "api", "path": "/var/log/api.log"}]}
            }]}
            (home / "profiles.json").write_text(json.dumps(profile), encoding="utf-8")
            ssh_command = json.dumps([sys.executable, str(ROOT / "tests" / "fake_ssh.py")])
            env = {**os.environ, "SSH_REMOTE_MANAGER_HOME": str(home),
                   "SSH_REMOTE_MANAGER_SSH": ssh_command}
            process = subprocess.Popen([sys.executable, str(ROOT / "server" / "ssh_remote_mcp.py")],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True, env=env)

            def call(identifier: int, method: str, params: dict | None = None) -> dict:
                request = {"jsonrpc": "2.0", "id": identifier, "method": method}
                if params is not None:
                    request["params"] = params
                process.stdin.write(json.dumps(request) + "\n")
                process.stdin.flush()
                return json.loads(process.stdout.readline())

            replies = [call(1, "initialize", {"protocolVersion": "2025-03-26"}),
                       call(2, "tools/list")]
            tools = [
                ("ssh_list_profiles", {}), ("ssh_get_profile", {"alias": "dev-one"}),
                ("ssh_test_connection", {"alias": "dev-one"}),
                ("ssh_get_server_info", {"alias": "dev-one"}),
                ("ssh_service_status", {"alias": "dev-one", "service": "api"}),
                ("ssh_read_logs", {"alias": "dev-one", "target": "api", "lines": 5}),
                ("ssh_audit_recent", {"limit": 20}),
            ]
            for index, (name, args) in enumerate(tools, 3):
                replies.append(call(index, "tools/call", {"name": name, "arguments": args}))
            process.stdin.close()
            process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()
            serialized = json.dumps(replies)
            self.assertNotIn(secret, serialized)
            self.assertNotIn("hunter2", serialized)
            self.assertNotIn("abc123", serialized)
            listed = replies[1]["result"]["tools"]
            self.assertEqual({tool["name"] for tool in listed}, {name for name, _ in tools})
            for reply in replies:
                self.assertNotIn("error", reply)


if __name__ == "__main__":
    unittest.main()
