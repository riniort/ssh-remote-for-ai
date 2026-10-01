# Threat Model

## Scope

This threat model covers the local GUI, secretless JSON profile store, generated managed blocks in `~/.ssh/config`, local MCP server, `ssh.exe` child processes, local audit JSONL, and the configured SSH endpoints. It covers Phase 1 read-only tools only.

Out of scope are protecting a fully compromised operating-system administrator, repairing a compromised remote host, making local audit cryptographically nonrepudiable, and arbitrary mutation features that do not exist in Phase 1.

## Assets

The primary assets are:

- private keys and any key passphrases;
- integrity of SSH destinations, usernames, host-key trust, and per-profile policy;
- confidentiality of remote operational output;
- integrity of unmanaged `~/.ssh/config` content;
- availability of the workstation and remote services;
- accuracy and confidentiality of local audit metadata; and
- the user's intent, especially around production systems and destructive lifecycle actions.

Public keys and profile metadata are less sensitive than private keys, but they can reveal infrastructure inventory and must still be scoped appropriately.

## Actors and trust assumptions

- **User/operator:** trusted to verify host fingerprints, authorize profile/key lifecycle changes, and protect the workstation account.
- **AI/MCP client:** potentially confused, prompt-injected, or malicious. It receives only the least privilege provided by the MCP tools.
- **Local MCP server and GUI:** trusted code, but all file and request inputs they parse are untrusted.
- **Remote host:** authenticated by its host key but not trusted to return safe content.
- **Local same-user process:** outside the plugin trust boundary and capable of attacking local files or binaries.
- **Package/update source:** trusted only after provenance and integrity verification.

The design does not assume that natural-language confirmation from an AI is equivalent to human authorization.

## Entry points

- MCP tool parameters and protocol messages;
- JSON profile and policy files, including hand-edited or downgraded data;
- legacy and unmanaged SSH config text;
- public-key onboarding and revoke workflows in the GUI;
- stdout, stderr, exit status, timing, and volume from `ssh.exe` and the remote host;
- the executable search path and environment inherited by child processes;
- audit file reads and rotation; and
- plugin install/update/uninstall scripts.

## Threats and mitigations

| Threat | Example | Primary mitigations | Residual risk |
|---|---|---|---|
| Private-key disclosure | Agent requests a key path/content; exception dumps a file | MCP schema has no key-content operation; responses omit key path; readiness is a status; never open key bytes; exception/output scanning tests | Same-user malware or a compromised runtime can access files |
| Password capture | Tool prompts for a password or stores one in a profile | No password field; `BatchMode=yes`; bounded process lifetime; documentation forbids sharing passwords | Users can expose credentials outside the product |
| Local command injection | Alias such as `-oProxyCommand=...` changes invocation | Conservative validation; reject leading `-`; argument arrays; no `shell=True`; known executable; option terminators | Vulnerabilities in OpenSSH or runtime remain possible |
| Remote command injection | Service or path contains shell syntax | Exact allowlist lookup; fixed command templates; conservative service identifiers; no arbitrary path; no raw command tool | A wrongly authored constant/template may still be unsafe |
| Option injection | Host/user/alias begins with `-` | Validate all stored and request values; arguments ordered behind terminators where supported | Third-party command parsers may have unexpected behavior |
| Path traversal | Key or log target uses `..`, UNC, ADS, symlink escape | Canonicalize local key paths beneath `~/.ssh`; reject reparse escapes; remote logs use named mappings only | Filesystem races require careful open/verify behavior |
| Alias collision/config takeover | Managed alias overlaps `Host *` or unmanaged host | Detect every concrete `Host` token; reject collision; wildcard/Include remain read-only until explicit import | Included files may change after validation |
| Destructive config rewrite | Parser consumes unmanaged lines or crash truncates file | Exact marker ownership; reject malformed markers; backup; lock; same-directory temp and atomic replace; migration tests | Filesystem/antivirus behavior may weaken atomicity |
| Lost key on rename/delete | Profile operation moves or removes key unexpectedly | Rename preserves key reference; revoke/profile removal/key deletion are separate; explicit confirmations; dependency checks | Manual filesystem deletion is outside product control |
| Host impersonation/MITM | MCP auto-accepts an unknown or changed key | Human fingerprint verification during onboarding; strict checking thereafter; changed keys fail closed | User may verify through a compromised channel |
| Prompt injection from logs | Log line instructs the agent to deploy or reveal data | Treat remote output as untrusted data; no mutation/raw-shell tools; bound and redact output; agent instructions require policy checks | Output can still influence downstream human/agent decisions |
| Secret leakage in output | Logs include token or connection string | Narrow allowlists; byte limits; streaming-aware redaction; do not audit output | Novel/encoded secrets may evade redaction |
| Denial of service | Remote streams forever or emits huge stderr | Connect and overall timeout; concurrent bounded reads; byte caps; kill process tree; optional rate/concurrency limits | Repeated valid calls can still consume resources |
| Production mutation | Agent attempts restart/deploy on production | No Phase 1 mutation tools; production read-only policy enforced server-side in MCP; unknown capabilities fail closed | Direct SSH outside the plugin remains possible |
| Policy bypass by file tampering | Profile relabeled development or allowlist widened | Restrictive local ACLs; validate schema on every use; audit profile administration; future signed-policy option | Same-user/administrator tampering cannot be prevented locally |
| Audit data leak | Audit records raw stderr or environment | Strict event schema; metadata only; redaction; restrictive ACLs; bounded retention | Infrastructure inventory remains in metadata |
| Audit tampering | Attacker edits, inserts, reorders, or deletes evidence | Cross-process append lock; sequence and SHA-256 hash-chain verification; rotation discipline | Same-user attacker can replace the full chain and recompute hashes without an external anchor |
| Executable substitution | Malicious `ssh.exe` earlier on PATH | Resolve/record a trusted executable path; reject test override in production; package integrity checks | Trusted binary or update channel may be compromised |
| Unsafe SSH directives | Imported `ProxyCommand`, forwarding, or wildcard changes behavior | Import only a narrow directive set; generate known-safe blocks; reject dangerous directives; unmanaged text untouched | Global unmanaged config may still affect matching hosts unless isolated |
| Concurrent-write corruption | Two GUIs update JSON/config simultaneously | Cross-process lock, reread under lock, version check, atomic replacement | Stale lock recovery can be implemented incorrectly |
| Supply-chain compromise | Plugin/update runs altered code | Minimal dependencies, pinned/verified artifacts, reviewable install scripts, no global install before approval | Build infrastructure remains a trust dependency |

## Abuse cases to test

Security tests must include at least:

- aliases, hosts, and users containing leading dashes, whitespace, newlines, Unicode confusables, wildcards, path separators, and shell metacharacters;
- service names and log target names containing separators, substitutions, quotes, control characters, traversal, and option prefixes;
- malicious values inserted directly into the JSON file, bypassing the GUI;
- legacy blocks with mismatched, duplicate, nested, or unterminated markers;
- unmanaged concrete hosts, `Host *`, wildcard hosts, `Match`, and `Include` entries;
- key paths outside `~/.ssh`, through `..`, alternate data streams, UNC paths, junctions, and symlinks;
- stdout and stderr that exceed limits, never close, split secrets across chunks, contain binary data, or contain private-key markers;
- unknown and changed host keys, missing keys, authentication failures, DNS failures, unreachable hosts, and timeout races;
- concurrent writers, forced process termination between temporary write and replace, and failed backup creation;
- production profiles with missing, malformed, or mutation-looking capability values;
- MCP requests with extra fields, wrong types, huge values, and unknown aliases; and
- scans proving that private-key fixtures never appear in MCP output, audit files, logs, snapshots, or exception text.

Integration tests inject a fake SSH executable and must not depend on network availability or a real server.

## Security review gates

A release is not ready until:

1. all tool inputs have explicit schemas and negative tests;
2. every SSH invocation is traceable to an argument-array construction and fixed remote template;
3. key non-disclosure tests cover success and every error path;
4. managed-config preservation, backup, locking, and atomicity tests pass on Windows;
5. production policy tests prove mutation is unavailable and unknown capabilities fail closed;
6. timeout, byte-limit, process-tree cleanup, and redaction tests pass for both stdout and stderr;
7. plugin installation remains local and unactivated until owner approval; and
8. no test or setup step contacts a real SSH endpoint.

## Residual-risk acceptance

Release notes must carry forward unresolved residual risks from [SECURITY.md](SECURITY.md). Adding a new tool, backend, accepted SSH directive, credential mechanism, or mutation capability requires updating this threat model before implementation is considered complete.
