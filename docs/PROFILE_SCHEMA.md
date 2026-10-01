# Profile schema

`%USERPROFILE%\.ssh\ssh-remote-manager\profiles.json` is the single source of truth. It contains no password or key material. `identityFile` is a local path reference and must resolve beneath `%USERPROFILE%\.ssh`.

```json
{
  "schemaVersion": 1,
  "profiles": [
    {
      "alias": "dev-one",
      "displayName": "Development API",
      "host": "dev.example.test",
      "port": 22,
      "user": "deploy",
      "environment": "development",
      "identityFile": "C:\\Users\\me\\.ssh\\ssh_remote_manager_dev-one",
      "capabilities": {
        "serverInfo": true,
        "systemd": true,
        "docker": false,
        "logs": true
      },
      "allowlists": {
        "services": ["api.service"],
        "logTargets": [
          {"name": "api", "path": "/var/log/api/app.log"}
        ]
      },
      "lastTestedUtc": "2026-10-01T08:00:00Z"
    }
  ]
}
```

Aliases are 1–64 ASCII letters, digits, dot, underscore, or hyphen and cannot begin with an option prefix. Environment is exactly `development`, `staging`, or `production`. Service names and log target names use restricted character sets. Log paths are absolute, have no traversal segments, and are selected by name through MCP; callers cannot submit arbitrary paths.

The GUI writes JSON atomically under a lock, then generates only blocks delimited by:

```text
# BEGIN SSH REMOTE MANAGER: dev-one
# END SSH REMOTE MANAGER: dev-one
```

Legacy `KEBLM MANAGED SSH` blocks remain readable and migrate on startup. Rewrite preserves unmanaged content and creates a timestamped SSH config backup. A rename changes only profile metadata and managed block alias; the key path remains stable.
