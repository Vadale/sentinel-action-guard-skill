# Operator setup and recovery

Linux only: Python 3.11+ standard library, `/proc`, Unix sockets, a controlling
terminal, and an existing Rust/Cargo toolchain with a C compiler/linker. The
engineering target is Python 3.15.0 and Rust/Cargo 1.99.1. Other versions are not
certified; the upstream `rust-version=1.75` field is not a tested minimum for this
resolved dependency graph. First build fetches Cargo.lock dependencies from
crates.io; the running route uses an offline StubChecker and no model service.

Use absolute paths. `SKILL` below means this skill directory. Select a local
filesystem supporting permissions, Unix sockets and hard links. Keep build and
store paths outside the distributed skill. Existing paths are never replaced.

```sh
python "$SKILL/scripts/sentinel.py" build /absolute/new/sentinel-build
python "$SKILL/scripts/sentinel.py" init /absolute/new/sentinel-store
```

Build creates a source copy, isolated Cargo cache, target and temp directories.
It uses `cargo build --locked --jobs 2`; it does not install Rust or alter global
Cargo configuration. Keep the final JSON engine path from stdout. Dependencies
may still require access through the machine's ordinary network configuration.

The operator can edit the newly created `config.json` **before** starting a run:

```json
{"version":1,"slots":{"draft":{"file":"draft.md","decision":"allow"},"reviewed":{"file":"reviewed.md","decision":"ask"},"locked":{"file":"locked.md","decision":"deny"}}}
```

These decisions govern **writes**. Reads of enrolled text files are allowed.
Enroll 1–32 unique slots and single filenames; no directory paths, duplicate
keys, unknown fields or filename reuse. Slot IDs use lowercase letters, digits
and hyphens; filenames use letters, digits, dots, underscores and hyphens and
start with a letter or digit. Both have a 64-character maximum. Do not expose the
configuration or control directory as agent-editable resources. Enrollment is
loaded once per operator run; editing a live config is not a policy update.

In a dedicated operator terminal:

```sh
python "$SKILL/scripts/sentinel.py" operator \
  --root /absolute/new/sentinel-store \
  --engine /absolute/new/sentinel-build/target/debug/sentinel-engine \
  --approval-timeout 60
```

Startup stdout prints a JSON receipt with `root`, a fresh `run` ID and a `command`
array. Configure a stdio MCP client to launch that **exact command**: executable
is the first array element, arguments are the remainder. The command invokes
`connect --root ... --run ...`; no client name or configuration file format is
assumed. Keep the foreground operator terminal available for review. It must be
separate from the agent/client terminal. No background service is installed.

For an `ask` write the operator sees JSON-escaped exact content, slot, path,
UTF-8 byte count and SHA-256. Type the displayed `approve CHALLENGE` only after
review; any other submitted line refuses. The challenge is single-use and bound
to this run/request/content. Default expiry is 60 seconds; the option accepts
0.05–300 seconds. The agent has no approval tool. Do not type approval in the
agent's conversation or stdin. An actual human should review content; scripted
operator tests only establish engineering behavior.

One actor connection and one pending operation are supported. Disconnect ends
the run and invalidates outstanding approval. Restarting requires a new operator
process and its fresh command; do not reuse an old run ID. `Ctrl-C` ends the
foreground operator; inspect any already delivered files before another attempt.
Never automatically retry a write whose response was lost.

Artifacts are under `ROOT/artifacts`. Private metadata is in
`ROOT/control/audit.sqlite3` and `executor.jsonl`. Logs contain request metadata,
paths and digests, not artifact bodies; the operator terminal does display bodies.
These logs are local diagnostics, not an external tamperproof audit. A failure
after filesystem commit may have an unknown delivery outcome; inspect before
retrying. Writes never overwrite; use a newly enrolled filename/store for a new
version after an operator decision.

Troubleshooting: missing terminal, invalid policy/config, unsafe directory,
active lock, missing engine, unavailable audit or expired approval stops or
rejects execution. Check the reported cause and operator diagnostics. Do not
delete a lock file to bypass an active process or replace an occupied socket.
The lock file persists normally; flock ownership ends with the process. Cleanup
removes only this run's unchanged socket and empty run directory; unexpected
replacement paths are left for inspection.

Advanced: `serve --root ROOT --engine BINARY` retains direct stdio for a headless
host with a distinct controlling terminal and **no competing terminal reader**.
An interactive host sharing `/dev/tty` can steal input; prefer `operator/connect`.
