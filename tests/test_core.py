from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from server.core import ProfileStore, SrmError, SshRemoteService, SshRunner, redact, sanitize_error


def payload(identity: str = "~/.ssh/id_secret") -> dict:
    return {"schemaVersion": 1, "profiles": [{
        "alias": "dev-one", "displayName": "Dev One", "host": "dev.example.test",
        "port": 22, "user": "deploy", "environment": "development",
        "identityFile": identity,
        "capabilities": {"serverInfo": True, "systemd": True, "docker": True, "logs": True},
        "allowlists": {"services": ["api.service", "api"],
                       "logTargets": [{"name": "api", "path": "/var/log/api/app.log"}]},
        "lastTestedUtc": None,
    }]}


class CoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)
        (self.home / "profiles.json").write_text(json.dumps(payload()), encoding="utf-8")
        self.runner = SshRunner([sys.executable, str(ROOT / "tests" / "fake_ssh.py")],
                                timeout_seconds=1, output_limit=2048)
        self.service = SshRemoteService(ProfileStore(self.home), self.runner)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_list_and_get_never_expose_identity_file(self) -> None:
        details = self.service.get_profile("dev-one")
        self.assertFalse(details["keyReady"])
        serialized = json.dumps([self.service.list_profiles(), details])
        self.assertNotIn("identityFile", serialized)
        self.assertNotIn("id_secret", serialized)

    def test_unknown_and_malicious_alias_are_rejected(self) -> None:
        for value in ["-oProxyCommand=calc", "dev;whoami", "../dev", "unknown"]:
            with self.subTest(value=value), self.assertRaises(SrmError):
                self.service.get_profile(value)

    def test_service_and_path_are_exact_allowlists(self) -> None:
        with self.assertRaises(SrmError):
            self.service.service_status("dev-one", "api;id")
        with self.assertRaises(SrmError):
            self.service.service_status("dev-one", "not-allowed")
        with self.assertRaises(SrmError):
            self.service.read_logs("dev-one", "../../etc/passwd")

    def test_ssh_uses_array_strict_options_and_option_terminator(self) -> None:
        record = self.home / "args.json"
        with patch.dict(os.environ, {"FAKE_SSH_RECORD": str(record)}):
            result = self.service.service_status("dev-one", "api.service")
        self.assertTrue(result["success"])
        args = json.loads(record.read_text(encoding="utf-8"))
        self.assertIn("BatchMode=yes", args)
        self.assertIn("StrictHostKeyChecking=yes", args)
        self.assertEqual(args[args.index("--") + 1], "dev-one")

    def test_redaction_covers_common_secret_shapes(self) -> None:
        value = redact("password=hunter2 token: abc Authorization: Bearer xyz postgres://u:p@h/db")
        self.assertNotIn("hunter2", value)
        self.assertNotIn("abc", value)
        self.assertNotIn("xyz", value)
        self.assertNotIn("u:p", value)

    def test_error_sanitization_removes_private_key_paths(self) -> None:
        value = sanitize_error(r"no such identity: C:\Users\alice\.ssh\prod-key: No such file")
        self.assertNotIn("prod-key", value)
        self.assertNotIn(r"C:\Users", value)
        self.assertIn("[path]", value)

    def test_log_output_is_redacted(self) -> None:
        result = self.service.read_logs("dev-one", "api")
        combined = result["output"] + result["error"]
        for secret in ["hunter2", "abc123", "user:pass"]:
            self.assertNotIn(secret, combined)

    def test_timeout_and_output_limit(self) -> None:
        with patch.dict(os.environ, {"FAKE_SSH_MODE": "timeout"}):
            result = self.runner.run("dev-one", ["true"])
        self.assertEqual(result.status, "timeout")
        with patch.dict(os.environ, {"FAKE_SSH_MODE": "large"}):
            result = self.runner.run("dev-one", ["true"])
        self.assertTrue(result.truncated)
        self.assertLessEqual(len(result.stdout.encode()), 2048)

    def test_unknown_host_and_unreachable_are_sanitized_categories(self) -> None:
        with patch.dict(os.environ, {"FAKE_SSH_MODE": "unknown_host"}):
            self.assertEqual(self.runner.run("dev-one", ["true"]).status, "unknown_host")
        with patch.dict(os.environ, {"FAKE_SSH_MODE": "unreachable"}):
            result = self.runner.run("dev-one", ["true"])
        self.assertEqual(result.status, "unreachable")

    def test_production_profile_has_no_mutation_surface(self) -> None:
        data = payload()
        data["profiles"][0]["environment"] = "production"
        (self.home / "profiles.json").write_text(json.dumps(data), encoding="utf-8")
        method_names = {name for name in dir(self.service) if not name.startswith("_")}
        self.assertFalse(method_names & {"restart", "deploy", "execute", "shell", "migrate"})

    def test_ssh_config_reference_uses_existing_target_alias(self) -> None:
        data = payload("")
        data["profiles"][0].update({"alias": "friendly-prod", "environment": "production",
                                    "connectionMode": "ssh-config-alias",
                                    "sshConfigAlias": "existing-prod", "identityFile": ""})
        (self.home / "profiles.json").write_text(json.dumps(data), encoding="utf-8")
        record = self.home / "reference-args.json"
        with patch.dict(os.environ, {"FAKE_SSH_RECORD": str(record)}):
            details = self.service.get_profile("friendly-prod")
            result = self.service.test_connection("friendly-prod")
        self.assertTrue(result["success"])
        self.assertIsNone(details["keyReady"])
        self.assertEqual(details["authSource"], "ssh-config")
        self.assertNotIn("sshConfigAlias", details)
        args = json.loads(record.read_text(encoding="utf-8"))
        self.assertEqual(args[args.index("--") + 1], "existing-prod")

    def test_duplicate_alias_rejected_case_insensitively(self) -> None:
        data = payload()
        duplicate = dict(data["profiles"][0])
        duplicate["alias"] = "DEV-ONE"
        data["profiles"].append(duplicate)
        (self.home / "profiles.json").write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaises(SrmError):
            self.service.list_profiles()


if __name__ == "__main__":
    unittest.main()
