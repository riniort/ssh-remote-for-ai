# Troubleshooting and revocation

## Unknown host or host-key failure

MCP intentionally does not bypass strict host-key checks. Verify the fingerprint out of band, onboard it using a terminal you control, then retry. If a known host key unexpectedly changes, stop and investigate instead of deleting the warning blindly.

## Missing key

Open the GUI, select the profile, and generate or locate its dedicated key. Copy only the public `.pub` value. Never paste the private key, a password, token, or connection string into Codex.

## Authentication failed

Confirm the public key is in the intended user's `~/.ssh/authorized_keys`, permissions are correct, and the profile user is correct. `BatchMode=yes` means MCP will not prompt for a password.

## Unreachable server

Check DNS, VPN/firewall access, host and port from a terminal you control. MCP errors are sanitized and intentionally omit full command output.

## Service or log target rejected

Do not guess another name or path. Add the exact service or named log target to the profile in the GUI after reviewing its environment and least-privilege need.

## Safe revocation workflow

1. In the GUI, select the correct profile and copy its revoke command.
2. Review and run it in a trusted session on the server. Confirm the public key is no longer authorized.
3. Remove the local profile if it is no longer needed. This does not delete keys.
4. Optionally use the separate “Delete local key” action after confirming no other server needs it.

Removing a profile alone does not revoke access. Deleting a local key alone does not remove its public key from a server.

## Recovery

Managed SSH config rewrites create timestamped `config.*.bak` files. Profile JSON uses atomic replacement and a lock file. Restore only after closing the GUI and confirming which file is authoritative; never merge private-key content into the JSON store.
