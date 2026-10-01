---
name: manage-ssh-remotes
description: Safely inspect servers through the SSH Remote Manager MCP using configured profile aliases and read-only policy. Use for SSH connection checks, server summaries, allowlisted systemd or Docker status, allowlisted log tails, profile metadata, and local SSH audit history.
---

# Manage SSH remotes

1. Call `ssh_list_profiles` before using a profile unless the same verified list is already in the current task.
2. Check the profile environment before every remote call. Treat production as read-only and high risk.
3. Start with metadata or connection tests, then use the narrowest read-only tool that answers the request.
4. Use only aliases, services, and log targets returned by the tools. Never guess them.
5. Never ask for, read, print, transmit, or reconstruct a private key or password.
6. Stop if the requested service or log target is not allowlisted. Ask the user to update policy in the GUI.
7. Do not attempt raw commands, shells, deploys, restarts, migrations, or configuration changes. Phase 1 has no mutation tools.
8. Report sanitized errors and the affected environment clearly. Do not work around strict host-key failures.
9. Use `ssh_audit_verify` when audit integrity matters; a failed verification requires human review before trusting recent records.
