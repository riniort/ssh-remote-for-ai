#!/usr/bin/env python3
"""Deterministic fake OpenSSH executable used only by automated tests."""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path


record = os.environ.get("FAKE_SSH_RECORD")
if record:
    Path(record).write_text(json.dumps(sys.argv[1:]), encoding="utf-8")

mode = os.environ.get("FAKE_SSH_MODE", "success")
if mode == "timeout":
    time.sleep(5)
if mode == "unknown_host":
    print("Host key verification failed.", file=sys.stderr)
    raise SystemExit(255)
if mode == "unreachable":
    print("ssh: connect to host example port 22: Connection timed out", file=sys.stderr)
    raise SystemExit(255)
if mode == "large":
    print("X" * 200000)
    raise SystemExit(0)

remote = sys.argv[sys.argv.index("--") + 2:] if "--" in sys.argv else []
if remote[:1] == ["true"]:
    raise SystemExit(0)
if remote[:1] == ["systemctl"]:
    print("ActiveState=active\nSubState=running\nLoadState=loaded")
elif remote[:1] == ["docker"]:
    print("running")
elif remote[:1] == ["tail"]:
    print("normal log\npassword=hunter2\ntoken: abc123\npostgres://user:pass@db/name")
else:
    print("hostname=dev-box\nos=Linux x86_64\nuptime=up 2 days\nmemory=1G/4G\ndisk=10G/50G")
