# Boundaries and provenance

## What executes

Actor MCP → strict Python supervisor → real GuardianGateway/CompiledPolicy →
Rust Upstream → private execute handshake → descriptor-bound artifact executor.
Guardian records its audit decision before invoking Upstream. Python does not
interpret an advisory allow response as permission to execute on a separate path.
Artifact bodies stay in Python and the approval terminal; Guardian receives only
normalized metadata. The offline StubChecker supplies no independent semantic
or confidentiality analysis. The operator must review what the text means.

Default-deny policy trusts only supervisor-assigned operation IDs. Paths and
write decisions come from operator enrollment. Reads/writes check held directory
identities and regular files without following symlinks. New text is staged in
the private control directory and committed with an exclusive hard link. A
denied write does not invoke the executor; policy/audit activity is still an
expected internal effect. There is no overwrite, delete, arbitrary file path,
shell, network proxy, secret broker, remote checker or publication tool.

## Deployment limits

The guarantee applies only to these two tools on this Linux route. Socket mode
0600 and directory mode 0700 are local hygiene. A process with unrestricted
same-user shell, filesystem, process inspection or terminal access can bypass
the route or obtain its data. Procedural actor/operator roles are not OS
privilege isolation. Use a separately designed deployment boundary if an
adversarial process must be technically confined. This package installs none.

The engine audit and executor journal are local files. Same-user modification,
crash/power-loss durability, malicious operator/toolchain, resource attacks
outside bounded application queues and system-wide safety are not certified.
Bodies appear in operator terminal history and in artifact files. Prompts and
approvals are not an automatic publication relevance or sensitive-data review.

Engineering checks use subprocess MCP clients, synthetic fixtures and separate
scripted PTY operators with independent filesystem observation. Fresh model-agent
trials, when reported, remain internal tests; no actual customer, named GUI host
or usability study follows from them. Broader model security, universal prompt
injection prevention and every-tool interception are not claims of this skill.

## Source and terms

Based on Project Guardian source commit
`c64458b0117fc74b8135450af98ea09d0636d59b`, Apache-2.0. Six crates are copied
unchanged under `runtime/vendor`: guardian-core, guardian-policy, guardian-audit,
guardian-checker, guardian-broker and guardian-mcp-gateway. Two original policy
fixtures are retained for upstream test compilation. The root workspace,
resolved lock, execution wrapper, supervisor and skill documentation are adapted
or new integration work; they are not upstream supported client integrations.
The original project is neither required at runtime nor modified by setup.

Broker code contains credential/keychain implementations as an upstream
dependency, but the Sentinel route does not invoke those backends. No login,
keychain provisioning, CA, service or API key is required. Dependencies retain
their own terms; Cargo.lock pins their identities. Source distribution includes
Apache-2.0 license and NOTICE; downloaded crates carry their upstream licenses.
