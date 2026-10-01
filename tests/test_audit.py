from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from server.core import AuditLog


class AuditLogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def append(self, audit: AuditLog, index: int = 0) -> None:
        audit.append(tool="ssh_test_connection", profile={"alias": "dev-one", "environment": "development"},
                     duration_ms=index, category="success", success=True,
                     request_id=f"request-{index}")

    def test_hash_chain_detects_record_tampering(self) -> None:
        audit = AuditLog(self.home)
        for index in range(3):
            self.append(audit, index)
        verified = audit.verify()
        self.assertTrue(verified["valid"])
        self.assertEqual(verified["recordsChecked"], 3)

        lines = audit.path.read_text(encoding="utf-8").splitlines()
        changed = json.loads(lines[1])
        changed["success"] = False
        lines[1] = json.dumps(changed, separators=(",", ":"))
        audit.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        result = audit.verify()
        self.assertFalse(result["valid"])
        self.assertEqual(result["error"], "record_hash_mismatch")

    def test_rotation_keeps_available_chain_verifiable(self) -> None:
        audit = AuditLog(self.home, max_bytes=900)
        for index in range(30):
            self.append(audit, index)
        self.assertTrue(audit.path.with_suffix(".jsonl.1").exists())
        result = audit.verify()
        self.assertTrue(result["valid"])
        self.assertGreater(result["recordsChecked"], 1)
        self.assertEqual(result["lastSequence"], 29)

    def test_legacy_log_is_preserved_before_starting_hash_chain(self) -> None:
        audit = AuditLog(self.home)
        audit.path.write_text('{"timestampUtc":"legacy"}\n', encoding="utf-8")
        self.append(audit)
        self.assertTrue(audit.verify()["valid"])
        self.assertEqual(len(list(self.home.glob("audit.legacy.*.jsonl"))), 1)

    def test_multiple_processes_append_without_corrupting_jsonl(self) -> None:
        code = (
            "from pathlib import Path; from server.core import AuditLog; import sys; "
            "a=AuditLog(Path(sys.argv[1])); prefix=sys.argv[2]; "
            "[a.append(tool='ssh_test_connection', profile={'alias':'dev-one','environment':'development'}, "
            "duration_ms=i, category='success', success=True, request_id=f'{prefix}-{i}') for i in range(15)]"
        )
        env = {**os.environ, "PYTHONPATH": str(ROOT)}
        processes = [subprocess.Popen([sys.executable, "-c", code, str(self.home), str(index)],
                                      cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      text=True) for index in range(4)]
        for process in processes:
            stdout, stderr = process.communicate(timeout=20)
            self.assertEqual(process.returncode, 0, stdout + stderr)
        audit = AuditLog(self.home)
        result = audit.verify()
        self.assertTrue(result["valid"])
        self.assertEqual(result["recordsChecked"], 60)
        self.assertEqual(len(audit.recent(100)), 60)


if __name__ == "__main__":
    unittest.main()
