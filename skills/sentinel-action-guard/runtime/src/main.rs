//! Private, bounded transport around the unchanged Guardian gateway.
//!
//! The supervisor owns artifact bytes and the operator terminal. This process
//! receives normalized metadata only; its sole execution port is a bound private
//! pipe exchange invoked by Guardian after approval and durable audit recording.

#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::fmt;
use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::sync::{Arc, Mutex};

use guardian_audit::AuditLog;
use guardian_checker::{Explanation, StubChecker};
use guardian_core::{Action, ActionKind, Capability};
use guardian_mcp_gateway::{
    ApprovalResponse, Approver, Gateway, GatewayOutcome, ToolCall, Upstream,
};
use guardian_policy::{CompiledPolicy, EvalEnv};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Map, Number, Value};

const MAX_LINE_BYTES: usize = 131_072;
const MAX_TEXT_BYTES: u64 = 16_384;
const MAX_POLICY_BYTES: u64 = 1_048_576;

// Errors deliberately carry no input, path, policy text, or upstream detail.
#[derive(Debug)]
struct ProtocolError;

type ProtocolResult<T> = Result<T, ProtocolError>;

/// Deserialize JSON while rejecting duplicate keys at every nesting level.
/// serde_json also rejects nonfinite numbers, invalid UTF-8 and trailing data.
struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StrictVisitor;

        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictValue;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("finite JSON without duplicate keys")
            }

            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Bool(value)))
            }

            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Number(value.into())))
            }

            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Number(value.into())))
            }

            fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
                Number::from_f64(value)
                    .map(|number| StrictValue(Value::Number(number)))
                    .ok_or_else(|| E::custom("nonfinite number"))
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::String(value.to_owned())))
            }

            fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::String(value)))
            }

            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }

            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }

            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<StrictValue>()? {
                    values.push(value.0);
                }
                Ok(StrictValue(Value::Array(values)))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut object: A) -> Result<Self::Value, A::Error> {
                let mut keys = HashSet::new();
                let mut values = Map::new();
                while let Some(key) = object.next_key::<String>()? {
                    if !keys.insert(key.clone()) {
                        return Err(de::Error::custom("duplicate key"));
                    }
                    let value = object.next_value::<StrictValue>()?;
                    values.insert(key, value.0);
                }
                Ok(StrictValue(Value::Object(values)))
            }
        }

        deserializer.deserialize_any(StrictVisitor)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
enum ArtifactTool {
    #[serde(rename = "artifact.read")]
    Read,
    #[serde(rename = "artifact.write.allow")]
    WriteAllow,
    #[serde(rename = "artifact.write.ask")]
    WriteAsk,
    #[serde(rename = "artifact.write.deny")]
    WriteDeny,
}

impl ArtifactTool {
    fn name(self) -> &'static str {
        match self {
            Self::Read => "artifact.read",
            Self::WriteAllow => "artifact.write.allow",
            Self::WriteAsk => "artifact.write.ask",
            Self::WriteDeny => "artifact.write.deny",
        }
    }

    fn kind(self) -> ActionKind {
        match self {
            Self::Read => ActionKind::FileRead,
            Self::WriteAllow | Self::WriteAsk | Self::WriteDeny => ActionKind::FileWrite,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Metadata {
    request_id: Value,
    slot: String,
    path: String,
    sha256: String,
    bytes: u64,
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_request_id(value: &Value) -> bool {
    match value {
        Value::String(text) => {
            !text.is_empty() && text.len() <= 256 && !text.chars().any(char::is_control)
        }
        Value::Number(number) => number.is_i64() || number.is_u64(),
        _ => false,
    }
}

impl Metadata {
    fn validate(&self, tool: ArtifactTool) -> ProtocolResult<()> {
        let slot_bytes = self.slot.as_bytes();
        let valid_slot = !slot_bytes.is_empty()
            && slot_bytes.len() <= 64
            && (slot_bytes[0].is_ascii_lowercase() || slot_bytes[0].is_ascii_digit())
            && slot_bytes
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-');
        // An enrolled path is absolute and already normalized by the supervisor.
        // Linux names can contain controls; JSON serialization escapes them.
        // Only NUL, dot segments and empty segments are invalid here. No
        // filesystem action or trust decision uses this metadata string.
        let valid_path = self.path.len() <= 4096
            && self.path.starts_with('/')
            && !self.path.contains('\0')
            && self
                .path
                .split('/')
                .skip(1)
                .all(|part| !part.is_empty() && part != "." && part != "..");
        let valid_payload = match tool {
            ArtifactTool::Read => self.bytes == 0 && self.sha256.is_empty(),
            _ => self.bytes <= MAX_TEXT_BYTES && valid_digest(&self.sha256),
        };
        if valid_request_id(&self.request_id) && valid_slot && valid_path && valid_payload {
            Ok(())
        } else {
            Err(ProtocolError)
        }
    }

    fn value(&self) -> ProtocolResult<Value> {
        serde_json::to_value(self).map_err(|_| ProtocolError)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CallRequest {
    op: String,
    id: u64,
    tool: ArtifactTool,
    args: Metadata,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalReply {
    op: String,
    call_id: u64,
    nonce: String,
    request_id: Value,
    sha256: String,
    decision: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecuteReply {
    op: String,
    call_id: u64,
    nonce: String,
    request_id: Value,
    sha256: String,
    ok: bool,
    result: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    slot: String,
    bytes: u64,
    sha256: String,
    #[serde(default)]
    created: Option<bool>,
}

#[derive(Clone)]
struct ActiveCall {
    id: u64,
    tool: ArtifactTool,
    args: Metadata,
    approval_sent: bool,
    approved: bool,
    execute_sent: bool,
}

impl ActiveCall {
    fn matches_call(&self, call: &ToolCall) -> bool {
        call.tool == self.tool.name()
            && call.kind == Some(self.tool.kind())
            && call.capability == Some(Capability::Filesystem)
            && self
                .args
                .value()
                .map(|args| args == call.args)
                .unwrap_or(false)
    }

    fn matches_action(&self, action: &Action) -> bool {
        action.tool == self.tool.name()
            && action.kind == self.tool.kind()
            && action.capability == Some(Capability::Filesystem)
            && self
                .args
                .value()
                .map(|args| args == action.args)
                .unwrap_or(false)
    }
}

struct Wire {
    input: BufReader<io::Stdin>,
    output: BufWriter<io::Stdout>,
    nonce: String,
    last_id: u64,
    active: Option<ActiveCall>,
    failed: bool,
}

impl Wire {
    fn new(nonce: String) -> Self {
        Self {
            input: BufReader::new(io::stdin()),
            output: BufWriter::new(io::stdout()),
            nonce,
            last_id: 0,
            active: None,
            failed: false,
        }
    }

    fn read(&mut self) -> ProtocolResult<Option<Value>> {
        let mut line = Vec::new();
        loop {
            let available = self.input.fill_buf().map_err(|_| ProtocolError)?;
            if available.is_empty() {
                return if line.is_empty() {
                    Ok(None)
                } else {
                    Err(ProtocolError)
                };
            }
            let newline = available.iter().position(|byte| *byte == b'\n');
            let length = newline.map(|index| index + 1).unwrap_or(available.len());
            if line.len().saturating_add(length) > MAX_LINE_BYTES {
                return Err(ProtocolError);
            }
            line.extend_from_slice(&available[..length]);
            self.input.consume(length);
            if newline.is_some() {
                let mut decoder = serde_json::Deserializer::from_slice(&line);
                let parsed = StrictValue::deserialize(&mut decoder).map_err(|_| ProtocolError)?;
                decoder.end().map_err(|_| ProtocolError)?;
                return Ok(Some(parsed.0));
            }
        }
    }

    fn send(&mut self, event: Value) -> ProtocolResult<()> {
        let bytes = serde_json::to_vec(&event).map_err(|_| ProtocolError)?;
        if bytes.len().saturating_add(1) > MAX_LINE_BYTES {
            return Err(ProtocolError);
        }
        self.output.write_all(&bytes).map_err(|_| ProtocolError)?;
        self.output.write_all(b"\n").map_err(|_| ProtocolError)?;
        self.output.flush().map_err(|_| ProtocolError)
    }

    fn next_call(&mut self) -> ProtocolResult<Option<(u64, ToolCall)>> {
        if self.failed || self.active.is_some() {
            return Err(ProtocolError);
        }
        let Some(value) = self.read()? else {
            return Ok(None);
        };
        let request: CallRequest = serde_json::from_value(value).map_err(|_| ProtocolError)?;
        if request.op != "call" || request.id <= self.last_id {
            return Err(ProtocolError);
        }
        request.args.validate(request.tool)?;
        let call = ToolCall {
            tool: request.tool.name().to_owned(),
            args: request.args.value()?,
            kind: Some(request.tool.kind()),
            capability: Some(Capability::Filesystem),
            session: Some(self.nonce.clone()),
        };
        self.last_id = request.id;
        self.active = Some(ActiveCall {
            id: request.id,
            tool: request.tool,
            args: request.args,
            approval_sent: false,
            approved: false,
            execute_sent: false,
        });
        Ok(Some((request.id, call)))
    }

    fn bound(
        &self,
        call: &ActiveCall,
        id: u64,
        nonce: &str,
        request_id: &Value,
        digest: &str,
    ) -> bool {
        call.id == id
            && self.nonce == nonce
            && call.args.request_id == *request_id
            && call.args.sha256 == digest
    }

    fn approval(&mut self, action: &Action) -> ProtocolResult<bool> {
        let active = self.active.clone().ok_or(ProtocolError)?;
        if self.failed
            || active.approval_sent
            || active.execute_sent
            || !active.matches_action(action)
        {
            return Err(ProtocolError);
        }
        // Consume the exchange before publishing it. Invalid, repeated or stale
        // replies cannot leave an unspent approval behind.
        self.active.as_mut().ok_or(ProtocolError)?.approval_sent = true;
        self.send(json!({
            "event": "approval", "call_id": active.id,
            "nonce": self.nonce, "args": active.args.value()?
        }))?;
        let reply: ApprovalReply = serde_json::from_value(self.read()?.ok_or(ProtocolError)?)
            .map_err(|_| ProtocolError)?;
        if reply.op != "approval"
            || !self.bound(
                &active,
                reply.call_id,
                &reply.nonce,
                &reply.request_id,
                &reply.sha256,
            )
        {
            return Err(ProtocolError);
        }
        self.active.as_mut().ok_or(ProtocolError)?.approved = reply.decision;
        Ok(reply.decision)
    }

    fn execute(&mut self, call: &ToolCall) -> ProtocolResult<Result<Value, String>> {
        let active = self.active.clone().ok_or(ProtocolError)?;
        if self.failed
            || active.execute_sent
            || !active.matches_call(call)
            || (active.approval_sent && !active.approved)
        {
            return Err(ProtocolError);
        }
        self.active.as_mut().ok_or(ProtocolError)?.execute_sent = true;
        self.send(json!({
            "event": "execute", "call_id": active.id,
            "nonce": self.nonce, "args": active.args.value()?
        }))?;
        let reply: ExecuteReply = serde_json::from_value(self.read()?.ok_or(ProtocolError)?)
            .map_err(|_| ProtocolError)?;
        if reply.op != "execute"
            || !self.bound(
                &active,
                reply.call_id,
                &reply.nonce,
                &reply.request_id,
                &reply.sha256,
            )
        {
            return Err(ProtocolError);
        }
        if !reply.ok {
            return Ok(Err("artifact execution failed".to_owned()));
        }
        // Read content stays in the supervisor. Only a receipt can cross back
        // through Guardian, so neither diagnostics nor actor bytes are echoed.
        let fields = reply.result.as_object().ok_or(ProtocolError)?;
        let valid_fields = match active.tool {
            ArtifactTool::Read => fields.len() == 3 && !fields.contains_key("created"),
            _ => fields.len() == 4 && fields.contains_key("created"),
        };
        let receipt: Receipt =
            serde_json::from_value(reply.result.clone()).map_err(|_| ProtocolError)?;
        let valid = valid_fields
            && receipt.slot == active.args.slot
            && receipt.bytes <= MAX_TEXT_BYTES
            && valid_digest(&receipt.sha256)
            && match active.tool {
                ArtifactTool::Read => receipt.created.is_none(),
                _ => {
                    receipt.bytes == active.args.bytes
                        && receipt.sha256 == active.args.sha256
                        && receipt.created == Some(true)
                }
            };
        if !valid {
            return Err(ProtocolError);
        }
        Ok(Ok(reply.result))
    }

    fn finish(&mut self, id: u64, outcome: GatewayOutcome) -> ProtocolResult<()> {
        if self.failed || self.active.as_ref().map(|active| active.id) != Some(id) {
            return Err(ProtocolError);
        }
        let (status, detail) = match outcome {
            GatewayOutcome::Allowed(receipt) => ("allowed", receipt),
            GatewayOutcome::Blocked(_) => ("blocked", json!("blocked by Guardian")),
            GatewayOutcome::UpstreamError(_) => {
                ("upstream_error", json!("artifact execution failed"))
            }
        };
        self.send(json!({ "event": "result", "call_id": id, "status": status, "detail": detail }))?;
        self.active = None;
        Ok(())
    }
}

#[derive(Clone)]
struct PrivatePort(Arc<Mutex<Wire>>);

impl PrivatePort {
    // These helpers are intentionally synchronous. No MutexGuard is held across
    // an await or moved into the async-trait future. The supervisor provides
    // approval deadlines and terminates the child on cancellation/disconnect.
    fn approve(&self, action: &Action) -> bool {
        let Ok(mut wire) = self.0.lock() else {
            return false;
        };
        match wire.approval(action) {
            Ok(decision) => decision,
            Err(_) => {
                wire.failed = true;
                false
            }
        }
    }

    fn forward_sync(&self, call: &ToolCall) -> Result<Value, String> {
        let Ok(mut wire) = self.0.lock() else {
            return Err("private execution channel failed".to_owned());
        };
        match wire.execute(call) {
            Ok(result) => result,
            Err(_) => {
                wire.failed = true;
                Err("private execution channel failed".to_owned())
            }
        }
    }
}

#[async_trait::async_trait]
impl Approver for PrivatePort {
    async fn request_approval(
        &self,
        action: &Action,
        _explanation: &Explanation,
    ) -> ApprovalResponse {
        if self.approve(action) {
            ApprovalResponse::Approved
        } else {
            ApprovalResponse::Denied
        }
    }
}

#[async_trait::async_trait]
impl Upstream for PrivatePort {
    async fn forward(&self, call: &ToolCall) -> Result<Value, String> {
        self.forward_sync(call)
    }
}

fn load_policy(path: &std::ffi::OsStr) -> ProtocolResult<CompiledPolicy> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| ProtocolError)?
        .take(MAX_POLICY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ProtocolError)?;
    if bytes.len() as u64 > MAX_POLICY_BYTES {
        return Err(ProtocolError);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| ProtocolError)?;
    CompiledPolicy::from_toml_str(text).map_err(|_| ProtocolError)
}

async fn run() -> ProtocolResult<()> {
    let argv: Vec<_> = std::env::args_os().collect();
    if argv.len() != 4 {
        return Err(ProtocolError);
    }
    let nonce = argv[3].to_str().ok_or(ProtocolError)?;
    if !(16..=128).contains(&nonce.len())
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(ProtocolError);
    }
    let policy = load_policy(&argv[1])?;
    let audit = AuditLog::open(&argv[2]).map_err(|_| ProtocolError)?;
    let wire = Arc::new(Mutex::new(Wire::new(nonce.to_owned())));
    let port = PrivatePort(Arc::clone(&wire));
    let gateway = Gateway::new(
        "sentinel-action-guard",
        policy,
        Box::new(StubChecker),
        Box::new(port.clone()),
        Box::new(port),
        audit,
        EvalEnv::default(),
    );
    gateway.audit_verify().map_err(|_| ProtocolError)?;
    wire.lock()
        .map_err(|_| ProtocolError)?
        .send(json!({ "event": "ready", "protocol": 1 }))?;
    loop {
        let next = wire.lock().map_err(|_| ProtocolError)?.next_call()?;
        let Some((id, call)) = next else {
            return Ok(());
        };
        let outcome = gateway.handle(call).await;
        wire.lock()
            .map_err(|_| ProtocolError)?
            .finish(id, outcome)?;
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if run().await.is_err() {
        // No dynamic error values: policy/audit paths and untrusted strings must
        // never become a diagnostic channel or an accidental protocol response.
        eprintln!("sentinel engine stopped (fail-closed)");
        std::process::exit(1);
    }
}
