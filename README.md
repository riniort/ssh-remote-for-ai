# SSH Remote Manager

SSH Remote Manager is a Windows GUI plus a personal Codex plugin/MCP server for using named SSH profiles without giving an AI a password or private-key content. The GUI owns profiles, keys, onboarding, and policy. The MCP companion exposes seven bounded, read-only Phase 1 tools.

## Safety boundary

- MCP accepts a configured profile alias, never arbitrary host credentials.
- Private keys remain under `%USERPROFILE%\.ssh`; key content and key paths are omitted from MCP responses.
- Passwords are never stored.
- OpenSSH runs with `BatchMode=yes`, strict host-key checking, timeouts, argument arrays, and bounded output.
- Services and log targets must be explicitly allowlisted per profile.
- `production` is read-only by default. Phase 1 has no arbitrary command, shell, deploy, restart, migration, or mutation tool.
- Tests use `tests/fake_ssh.py` and never contact a real server.

Read [the security model](docs/SECURITY.md) and [threat model](docs/THREAT_MODEL.md) before production use.

## Quick start

Requirements: Windows PowerShell 5.1 or newer, Python 3.10 or newer, and Windows OpenSSH Client.

1. Run `ssh_remote_manager.cmd` (the old `setup_remote_ssh_gui.cmd` launcher remains supported).
2. Create a profile, choose `development`, `staging`, or `production`, and define only the required capabilities and allowlists.
3. Generate a dedicated key. Copy only its `.pub` value or the generated installation command to a terminal you control.
4. Add the public key on the server without sending a password or private key to an AI.
5. Verify the host fingerprint through a trusted channel during onboarding. Subsequent MCP calls require strict host-key verification.
6. Test the profile in the GUI.

The canonical metadata store is `%USERPROFILE%\.ssh\ssh-remote-manager\profiles.json`. On startup, legacy blocks marked `KEBLM MANAGED SSH` migrate non-destructively to neutral `SSH REMOTE MANAGER` blocks. Unmanaged SSH config remains untouched and the config is backed up before rewrite.

## GUI usage

The dark-theme GUI supports create/view/edit/rename/remove, a dedicated key per managed profile, public-key generation/copy/install/revoke guidance, connection testing, environment warnings, last-test time, capabilities and allowlists. “Import existing SSH Host” imports only an exact unmanaged `Host` by reference, preserving its existing `ProxyJump`, authentication, and other OpenSSH directives without rewriting it. Wildcard, multi-host, and `Include` entries remain read-only.

Three destructive concepts stay separate:

1. Revoke the public key on the server using the copied revoke command.
2. Remove the local profile. This preserves local keys.
3. Delete the local key pair with the separate destructive confirmation. This does not revoke server access.

## Plugin installation

The repository is already a valid plugin root. Do not install it globally until you have reviewed the code and tests.

```powershell
./scripts/install.ps1 -WhatIf
./scripts/install.ps1
```

The installer copies the plugin to `%USERPROFILE%\plugins\ssh-remote-for-ai` and registers an `AVAILABLE` entry in the default personal marketplace. It does not activate the plugin, connect to SSH, or alter profiles/keys. After owner approval, add the plugin through the Codex plugin UI/CLI and start a new task so tools and skills reload.

Update and uninstall:

```powershell
./scripts/update.ps1
./scripts/uninstall.ps1 -WhatIf
./scripts/uninstall.ps1
```

Uninstall removes only the installed plugin and marketplace entry. Profiles, audit records, and SSH keys are preserved.

## MCP tools

| Tool | Purpose |
|---|---|
| `ssh_list_profiles` | List aliases and non-secret metadata |
| `ssh_get_profile` | Read metadata, environment, policy, and key-ready state |
| `ssh_test_connection` | Fixed BatchMode connection check |
| `ssh_get_server_info` | Fixed hostname/OS/uptime/CPU-memory-disk summary command |
| `ssh_service_status` | Read allowlisted systemd/Docker service status |
| `ssh_read_logs` | Read a bounded tail from a named allowlisted log target |
| `ssh_audit_recent` | Read sanitized local audit metadata |
| `ssh_audit_verify` | Verify audit sequence and SHA-256 hash-chain integrity |

Example requests:

```text
Development: list profiles, confirm dev-one is development, then test it.
Staging: show systemd status for the exact allowlisted api.service on staging-one.
Production: inspect prod-one metadata first, then read the exact allowlisted api log target; do nothing else.
```

Agents are instructed to list profiles first, verify environment, use the narrowest read-only tool, never guess an alias/service/path, and never seek private keys.

Audit writes are serialized across MCP processes. Each record contains a sequence number, request ID, previous hash, and its own SHA-256 hash. `ssh_audit_verify` detects modified, removed-from-the-middle, inserted, or reordered records within the retained log window. A pre-hardening audit is preserved as `audit.legacy.*.jsonl` before a new chain starts.

## Tests

```powershell
python -m unittest discover -s tests -p 'test_*.py' -v
Invoke-Pester -Script ./tests/ProfileStore.Tests.ps1
powershell -NoProfile -File ./tests/Test-PowerShellSyntax.ps1
python C:/Users/$env:USERNAME/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py .
```

The final validator path varies by Codex installation; use the bundled `plugin-creator` validator. Tests cover protocol smoke calls, fake SSH, injection attempts, timeouts, output limits, redaction, duplicate aliases, migration, unmanaged config preservation, key isolation, rename/delete semantics, and production defaults.

## More documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Profile schema](docs/PROFILE_SCHEMA.md)
- [Security model](docs/SECURITY.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Troubleshooting and revocation](docs/TROUBLESHOOTING.md)
- [Residual risks and Phase 2](docs/PHASE2.md)

No remote GitHub repository is created and no push, global activation, or real SSH connection is performed by development or tests.
