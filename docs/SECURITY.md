# Security Model

SSH Remote Manager gives an AI agent constrained visibility into preconfigured SSH targets. Its central security property is that an agent can request only named, policy-approved observations; it cannot obtain credentials or turn the integration into a general remote shell.

## Security guarantees in Phase 1

- MCP tools accept a profile alias, never raw connection parameters.
- The canonical JSON store contains metadata and policy but no password, token, private-key bytes, or key passphrase.
- Private keys remain beneath the user's `~/.ssh` directory. MCP responses omit their paths; readiness is represented as a status such as `available`, `missing`, or `invalid`.
- Remote activity is limited to fixed read-only probes in code and allowlisted service/log targets in the selected profile.
- Production receives the same read-only tool set and defaults to the most restrictive policy. There is no production mutation capability in Phase 1.
- Unknown hosts, missing policy, malformed state, unexpected schema versions, and ambiguous SSH configuration fail closed.
- No tool uses a shell to launch `ssh.exe`; executable and arguments are passed separately.

These guarantees reduce exposure but do not make a remote host or local workstation trustworthy. See the residual risks below.

## Input validation

Validation is applied before profile lookup and again before process creation.

- **Alias:** a short ASCII identifier with a conservative character set, for example letters, digits, dot, underscore, and hyphen; it cannot begin with `-`, contain whitespace, separators, wildcard syntax, control characters, or SSH keywords.
- **Host:** a validated DNS name, IPv4 address, or IPv6 literal. It cannot contain whitespace, control characters, shell metacharacters, URL syntax, or a leading option prefix.
- **User:** a conservative remote-account identifier; leading `-`, whitespace, separators, controls, and shell metacharacters are rejected.
- **Port:** an integer from 1 through 65535.
- **Environment:** exactly `development`, `staging`, or `production`.
- **Service/log target:** an exact lookup key in the profile allowlist, not a path or free-form fragment. Values loaded from disk are validated as untrusted input too.
- **Line count/timeouts:** integers clamped to configured safe bounds.
- **Key path:** canonicalized and verified to remain under the resolved `~/.ssh` root. Traversal, alternate data streams, devices, directories, and symlink/reparse-point escapes are rejected.

Arguments that can be interpreted as options are placed after option terminators where the called program supports them. Validation is not replaced by quoting.

## Credential handling

Passwords are intentionally unsupported. `BatchMode=yes` prevents password and passphrase prompts from stalling an unattended MCP process. The system does not scrape an SSH agent, export agent keys, or enumerate unrelated key files.

Private-key content must never be:

- opened to answer an MCP request;
- copied to the clipboard or UI;
- serialized to JSON or JSONL;
- included in a process argument;
- captured in test snapshots, exception messages, telemetry, or diagnostic bundles; or
- sent to an AI model.

The SSH client is given only the configured key path through the generated SSH config. File permissions should grant access only to the owning user and required system principals. Public keys are not secrets, but their display/copy/install/revoke workflows remain explicit because they grant access when installed remotely.

## Command execution controls

Local execution uses a known `ssh.exe` selected by trusted configuration or an absolute resolved path. Tests substitute a fake executable through an explicit test-only dependency-injection seam; production must not inherit that override from untrusted environment variables.

No request field becomes a local command string. Remote probes are selected from constant templates. For example, a systemd status request selects a fixed status operation and supplies a service only after exact allowlist lookup and strict validation. Docker inspection is available only if the profile explicitly grants the Docker backend. Log requests select a named mapping rather than accepting a path.

Every child process has:

- BatchMode enabled;
- an explicit connection timeout and an overall deadline;
- strict host-key checking after user-led onboarding;
- bounded stdout and stderr read concurrently;
- deterministic encoding/error handling; and
- process-tree termination on timeout or output overflow.

Exit codes and common OpenSSH failures are converted to stable categories. Raw stderr is not automatically safe to return.

## Production policy

`production` is a security boundary, not a display preference. The GUI uses a prominent warning treatment, and every MCP tool rechecks the stored environment at execution time. A caller cannot override the environment in a request.

In Phase 1, production can grant only read-only capabilities. Any unknown or future capability in a production profile is ignored or rejected by an older runtime. Restart, deployment, migration, file upload, port forwarding, interactive shell, and arbitrary command execution are unavailable for all environments.

## Redaction

Redaction occurs before data reaches an MCP response, audit writer, UI diagnostic, or exception renderer. It should cover, case-insensitively and across common encodings/forms:

- passwords, passphrases, bearer/API tokens, cookies, authorization headers, and private-key PEM/OpenSSH markers;
- connection strings and URL user-info;
- common secret-bearing environment assignments;
- cloud/provider credential formats known to the implementation; and
- sensitive local paths when not necessary for action.

Redaction is defense in depth, not permission to collect excess data. The preferred control is not to capture or persist full output. Redaction is tested with values split across chunks because streaming process output can divide a secret across read boundaries.

Sanitized errors contain the minimum needed to act: category, profile alias when safe, and a short recommendation. Detailed local diagnostics, if enabled for development, remain opt-in and still exclude credentials and key content.

## Audit and retention

The local append-only `%USERPROFILE%\.ssh\ssh-remote-manager\audit.jsonl` records UTC timestamp, tool, profile alias, environment, duration, outcome, and exit category. It never records full remote output, complete command arguments, environment variables, or secrets. A validated service/log target name may be recorded, but its mapped remote path is not necessary.

Rotation happens at a configured size and retention period. Rotated files inherit restrictive permissions. Rotation and append operations are synchronized so concurrent tool calls do not interleave or truncate JSON records. Audit integrity is best-effort local accountability, not tamper-proof evidence: a user or malware with the same privileges may alter it.

## SSH config and local-state safety

The application owns only complete blocks delimited by its neutral markers. It recognizes legacy KEBLM markers for migration but does not broaden ownership around them. All other config text is unmanaged and must be preserved.

Before rewrite, the application locks, validates, backs up, writes a same-directory temporary file, flushes, and atomically replaces. It rejects malformed or overlapping markers. JSON updates follow the same lock/temporary/replace discipline so a crash cannot create two competing authoritative states.

Profile removal, remote revocation, and local key deletion are separate confirmed workflows. Removing a profile never deletes a key, and uninstalling never deletes user SSH state.

## Host-key verification

MCP never auto-accepts an unknown host key. The initial fingerprint must be verified by a human through an independent channel and enrolled through the GUI/documented OpenSSH workflow. A changed fingerprint is treated as a possible interception or server rebuild and blocks access until the user investigates and explicitly updates trust.

## Safe operator practices

- Share only the public key with a server administrator or hosting panel. Never paste a password, private key, passphrase, token, or full environment dump into chat.
- Use a dedicated, least-privileged remote account for observation and restrict its server-side authorization where practical.
- Keep service and log allowlists narrow. Prefer a named log mapping over broad directory access.
- Review production profiles and recent audit events periodically.
- Revoke the public key on the server before removing a profile when access must end; then separately remove local metadata and, if no longer used, delete the local key.
- Treat a host-key change as a security event, not a connectivity nuisance.

## Residual risks

The following risks remain even with the controls above:

- A compromised remote host can return malicious or secret-bearing text. Output limits and redaction reduce, but cannot eliminate, data-exfiltration and prompt-injection risk.
- A process running as the same local user may read profile metadata, alter local state, tamper with the audit log, or invoke OpenSSH directly outside this plugin.
- A malicious or replaced `ssh.exe`, library, plugin package, or update can bypass application-level controls.
- Redaction is pattern-based and may miss novel, encoded, fragmented, or context-specific secrets.
- Read-only commands may still expose sensitive operational details and can impose load when called repeatedly.
- Server-side command semantics and permissions can change after a profile is approved.
- Backups of SSH config and rotated audits increase the number of local files requiring permission and retention hygiene.
- SSH agent forwarding, port forwarding, ProxyCommand-like behavior, and risky unmanaged config can change the effective connection behavior. Managed profiles should disable unnecessary forwarding and reject unsafe directives in imported material.
- Local audit is not cryptographically tamper-evident.

These are documented design constraints, not invitations to silently expand scope. Security-sensitive changes belong in the Phase 2 review process.
