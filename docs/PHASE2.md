# Phase 2 Roadmap

Phase 1 is intentionally read-only. This roadmap records possible future work; it does not grant permission to implement, expose, install, or activate any item below.

## Entry criteria

Phase 2 work should begin only after Phase 1 has passed protocol, security, migration, GUI, launcher, and fake-SSH integration tests; the owner has reviewed residual risks; and the plugin has been used safely in read-only mode. Each new capability requires an updated threat model and explicit owner approval.

## Candidate improvements

### Stronger local policy and integrity

- Split policy administration from ordinary profile metadata and optionally sign or protect policy with an OS-backed mechanism.
- Add restrictive ACL verification/repair for the state, key, backup, and audit paths.
- Add tamper-evident audit chaining and optional export to an owner-controlled sink. Export must remain metadata-only.
- Pin or verify the selected OpenSSH executable and packaged dependencies.
- Add explicit concurrency/rate budgets per profile and per tool.

### Safer host onboarding

- Provide a guided fingerprint workflow with independent-verification instructions and clear changed-key incident handling.
- Record verified fingerprint metadata without replacing OpenSSH's normal known-hosts enforcement.
- Support carefully reviewed host-certificate authorities for managed fleets.

Onboarding must never silently use `StrictHostKeyChecking=no` or treat an unverified network observation as proof of identity.

### Additional read-only capabilities

- Structured health checks defined as versioned, fixed templates.
- Narrow metrics queries with strict query and output budgets.
- More service managers only after backend-specific validation and tests.
- Improved structured parsing so the agent receives fields instead of raw terminal text.

New read-only tools still require explicit profile capabilities and narrow allowlists. A generic command runner is not a read-only feature.

### Key lifecycle improvements

- Guided key rotation that installs a new public key, verifies access, then separately revokes the old key.
- Hardware-backed or agent-backed keys without exporting key material.
- Detection of shared key references before local deletion.
- Recovery guidance for partial rotation and remote revocation failures.

Key generation, installation, revocation, profile removal, and local deletion remain distinct state transitions with independent audit and confirmation.

## Mutations: separate future design

Restart, deployment, migration, file transfer, and other mutations are not incremental additions to Phase 1. If pursued, they require a separate privileged service or tool namespace with all of the following controls:

- per-profile, per-environment, per-action opt-in policy;
- production denied by default, with no wildcard grants;
- fixed versioned action definitions rather than arbitrary commands;
- a human-readable plan showing exact target, environment, action, and bounded parameters;
- fresh explicit human confirmation bound to that plan and expiring quickly;
- replay protection and one-time authorization identifiers;
- least-privileged remote accounts and server-side restrictions;
- preconditions, timeout/rollback behavior, and idempotency where possible;
- metadata-only audit of requester, approver, plan identity, outcome, and duration; and
- tests proving that prompt injection or a compromised remote response cannot self-authorize a follow-up mutation.

Natural-language phrases from an agent or remote output do not count as confirmation. Approval for staging never authorizes production. A confirmation for one service, profile, or action cannot be reused for another.

## Explicit non-goals unless separately approved

- Arbitrary remote shell or raw command execution
- Password storage or password-based unattended login
- Private-key upload, display, backup, synchronization, or model access
- Silent host-key enrollment or changed-key acceptance
- SSH agent forwarding, general port forwarding, or ProxyCommand supplied by an MCP caller
- Automatic production deployment, restart, database migration, or remediation
- Uninstall that removes profiles, SSH config, audit history, or keys by default

## Suggested delivery sequence

1. Harden local ACL, executable provenance, rate limits, and audit integrity.
2. Improve structured read-only probes and host onboarding.
3. Add key rotation as a GUI-only, human-controlled workflow.
4. Prototype a distinct mutation authorization model against fake endpoints only.
5. Run an external security review and adversarial test suite.
6. Pilot opt-in mutations in development, then staging, with production still disabled.
7. Consider production only through a separate owner decision and documented risk acceptance.

## Phase 2 review checklist

For every proposal, reviewers should answer:

- What new asset or authority becomes reachable?
- Can the same outcome be achieved with a narrower read-only operation?
- Which exact request fields are attacker-controlled, and how are they validated?
- Can remote output or prompt injection cause the next action?
- How are production and non-production authorization separated?
- What does the user see and confirm, and how is confirmation bound to execution?
- What is written to audit, and can it expose secrets?
- How are timeout, output size, concurrency, retry, and rollback bounded?
- How do tests prove no private key, password, token, or connection string escapes?
- What happens if the process crashes at every state transition?

No candidate graduates from this roadmap merely because it is listed here.
