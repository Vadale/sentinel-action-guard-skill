# Minimal MCP client contract

Use this only when implementing a small client or engineering trial. Ordinary
MCP hosts handle framing. Launch the operator's `command` array as a subprocess
with stdin/stdout pipes and consume stderr separately. There is no approval API.
No global host configuration is needed to exercise this subprocess route.

Protocol version `2025-11-25`, UTF-8 JSON-RPC objects, one per newline. Send each
request and consume its response before another operation. Example startup:

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"artifact-demo","version":"1"}}}
{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
```

After initialization, discover slots from tools/list. Prepare real content from
the task, then call a tool, for example:

```json
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"write_artifact","arguments":{"slot":"draft","content":"# Run note\nA small synthetic example.\n"}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"read_artifact","arguments":{"slot":"draft"}}}
```

Parse `result.content[0].text` as a JSON object only on a successful response;
check JSON-RPC `error` and tool `isError` first. A write receipt is
`{slot,bytes,sha256,created:true}`. Readback is `{slot,bytes,sha256,content}`.
Verify UTF-8 bytes and SHA-256 against intended content. A missing response is
not a denial receipt and not permission to retry.

Only `read_artifact({slot})` and `write_artifact({slot,content})` are exposed.
Arguments have exact keys. No paths, shell, approval fields or tool-classification
hints are accepted. Text maximum 16,384 UTF-8 bytes; line maximum 131,072 bytes;
one pending operation; 1,024 unique integer/string request IDs per run. Batch,
scalar, duplicate-key and nonfinite JSON inputs reject. Use the negotiated
version or stop; no support for unrelated MCP extensions is claimed.

`ping` remains available while waiting for approval. To cancel a pending request
send `notifications/cancelled` with `params.requestId` equal to its original ID;
cancelled operations receive no tool response. Cancellation before commit
invalidates execution, but cannot undo a file already committed. Closing actor
stdin ends the connection/run; preserve unknown outcomes and do not replay.
Output backpressure and input floods can close or conservatively reject a run.

Specification references: [stdio transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports),
[lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle).
