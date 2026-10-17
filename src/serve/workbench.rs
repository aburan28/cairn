//! Authenticated, loopback-only editing of one local lab. This listener never
//! opens a ledger and is separate from the public, read-only workspace reader.

use std::collections::BTreeMap;
use std::io::{self, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value as Json};

use crate::canonical::Value;
use crate::crypto::identity::Identity;
use crate::lab::{api, collab, exec, state::State, store::Lab, LabError};

const MAX_CONNECTIONS: usize = 8;
const MAX_JOBS: usize = 32;

struct Job {
    request: Json,
    result: Json,
}

struct ReadIndex {
    space: String,
    ops: usize,
    graph: collab::Graph,
}

struct Session {
    id: String,
    lab: Mutex<Lab>,
    root: PathBuf,
    who: Identity,
    token: Result<Option<super::operator::Token>, String>,
    authority: String,
    jobs: Arc<Mutex<BTreeMap<String, Job>>>,
    offer: Option<crate::scheduling::ResourceOffer>,
    index: Mutex<Option<ReadIndex>>,
}

/// One session credential and one loopback listener. Dropping the process
/// invalidates the credential; it is never a peer identity or a ledger key.
pub struct Workbench {
    listener: TcpListener,
    session: Arc<Session>,
    url: String,
}

impl Workbench {
    /// Bind a numeric loopback address. Port zero selects a free port.
    pub fn bind(root: &Path, who: Identity, address: SocketAddr) -> Result<Self, LabError> {
        if !address.ip().is_loopback() {
            return Err(LabError::Refused(
                "the editing workbench must bind a loopback IP".into(),
            ));
        }
        let lab = Lab::open(root)?;
        if !State::of(&lab)
            .roster
            .has(&who.submitter_id(), crate::lab::op::Role::Writer)
        {
            return Err(LabError::Refused(
                "the workbench identity must be a lab writer".into(),
            ));
        }
        let listener = TcpListener::bind(address)?;
        let authority = listener.local_addr()?.to_string();
        let secret = format!("{}{}", collab::request_id()?, collab::request_id()?);
        let token = Ok(Some(
            super::operator::Token::parse(&secret).map_err(LabError::Invalid)?,
        ));
        let hardware = crate::network::Hardware::probe();
        let mut offer =
            super::resource_offer_from_env(&hardware).unwrap_or(crate::scheduling::ResourceOffer {
                cpus: hardware.cpus,
                memory_mb: hardware.memory_mb,
                cpu_millis: hardware
                    .cpu_millis
                    .or_else(|| hardware.cpus.and_then(|cpus| cpus.checked_mul(1000))),
                cpu: Some(hardware.cpu.clone()),
                concurrency: Some(1),
                gpus: None,
                storage_mb: None,
                pricing: None,
            });
        if let Some(path) = std::env::var_os(crate::agent::cli::RATE_CARD_ENV) {
            let bytes = std::fs::read_to_string(path)?;
            let value = Value::from_json(&bytes).map_err(|e| LabError::Invalid(e.to_string()))?;
            offer.pricing =
                Some(crate::pricing::RateCard::from_value(&value).map_err(LabError::Invalid)?);
        }
        Ok(Self {
            listener,
            url: format!("http://{authority}/#token={secret}"),
            session: Arc::new(Session {
                id: collab::request_id()?,
                lab: Mutex::new(lab),
                root: root.into(),
                who,
                token,
                authority,
                jobs: Arc::new(Mutex::new(BTreeMap::new())),
                offer: Some(offer),
                index: Mutex::new(None),
            }),
        })
    }

    /// Open this URL locally. The credential is a fragment, never an HTTP
    /// request target, query parameter, referrer or access-log entry.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Serve until killed. Requests have bounded framing, timeouts and a
    /// connection cap; slow clients do not hold the lab's mutation lock.
    pub fn serve(self) -> io::Result<()> {
        let active = Arc::new(AtomicUsize::new(0));
        for stream in self.listener.incoming() {
            let mut stream = stream?;
            if active.fetch_add(1, Ordering::AcqRel) >= MAX_CONNECTIONS {
                active.fetch_sub(1, Ordering::AcqRel);
                stream.set_write_timeout(Some(Duration::from_secs(2)))?;
                let _ = answer(
                    &mut stream,
                    503,
                    "application/json",
                    br#"{"error":"workbench busy; retry shortly"}"#,
                );
                continue;
            }
            let active = Arc::clone(&active);
            let session = Arc::clone(&self.session);
            std::thread::spawn(move || {
                struct Slot(Arc<AtomicUsize>);
                impl Drop for Slot {
                    fn drop(&mut self) {
                        self.0.fetch_sub(1, Ordering::AcqRel);
                    }
                }
                let _slot = Slot(active);
                let _ = handle(&mut stream, &session);
            });
        }
        Ok(())
    }
}

fn handle(stream: &mut TcpStream, session: &Session) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let request = match super::read_request(&mut reader) {
        Ok(request) => request,
        Err(error) => return error_response(stream, 400, &error, "invalid"),
    };
    // A credential alone must not turn an accidental reverse proxy or DNS
    // rebinding site into an editing endpoint. No CORS, cookies or redirects.
    if !stream.peer_addr()?.ip().is_loopback()
        || request.host.as_deref() != Some(&session.authority)
        || request.forwarded
        || request
            .origin
            .as_ref()
            .is_some_and(|v| v != &format!("http://{}", session.authority))
    {
        return error_response(
            stream,
            403,
            "use the workbench's exact local address",
            "refused",
        );
    }
    match (request.method.as_str(), request.target.as_str()) {
        ("GET", "/") => answer(
            stream,
            200,
            "text/html; charset=utf-8",
            include_bytes!("workbench/index.html"),
        ),
        ("GET", "/app.js") => answer(
            stream,
            200,
            "text/javascript; charset=utf-8",
            include_bytes!("workbench/app.js"),
        ),
        ("GET", "/model.js") => answer(
            stream,
            200,
            "text/javascript; charset=utf-8",
            include_bytes!("workbench/model.mjs"),
        ),
        ("GET", "/style.css") => answer(
            stream,
            200,
            "text/css; charset=utf-8",
            include_bytes!("workbench/style.css"),
        ),
        ("POST", "/api") => {
            if !super::operator::authorized(&session.token, request.authorization.as_deref()) {
                return error_response(
                    stream,
                    401,
                    "open the private link printed by cairn lab web",
                    "unauthorized",
                );
            }
            let bytes = match super::read_body(&mut reader, &request) {
                Ok(bytes) if request.content_type.as_deref() == Some("application/json") => bytes,
                Ok(_) => {
                    return error_response(stream, 415, "application/json required", "invalid")
                }
                Err((status, error)) => return error_response(stream, status, &error, "invalid"),
            };
            // Canonical parsing rejects duplicate keys and fractional numbers
            // before conversion to the shared collaboration boundary.
            let value = std::str::from_utf8(&bytes)
                .ok()
                .and_then(|s| Value::from_json(s).ok());
            let Some(value) = value else {
                return error_response(stream, 400, "invalid JSON body", "invalid");
            };
            let args: Json =
                serde_json::from_str(&value.canonical_string()).expect("canonical JSON");
            match call(session, &args) {
                Ok(value) => answer(
                    stream,
                    200,
                    "application/json",
                    value.to_string().as_bytes(),
                ),
                Err(error) => {
                    let (status, kind) = match &error {
                        LabError::Invalid(_) => (400, "invalid"),
                        LabError::Refused(_) => (409, "refused"),
                        LabError::NotFound(_) => (404, "not_found"),
                        LabError::Unavailable(_) => (503, "unavailable"),
                        _ => (500, "unavailable"),
                    };
                    error_response(stream, status, &error.to_string(), kind)
                }
            }
        }
        _ => error_response(stream, 404, "no such workbench route", "not_found"),
    }
}

fn call(session: &Session, envelope: &Json) -> Result<Json, LabError> {
    only(envelope, &["command", "args"])?;
    let command = text(envelope, "command")?;
    let args = &envelope["args"];
    if !args.is_object() {
        return Err(invalid("args must be an object"));
    }
    if command == "job" {
        only(args, &["id"])?;
        return session.jobs.lock().map_err(|_| invalid("job lock failed"))?
            .get(text(args, "id")?).map(|job| job.result.clone())
            .ok_or_else(|| LabError::NotFound("job not found; after restarting the workbench, inspect recorded runs before starting another".into()));
    }
    let mut lab = session.lab.lock().map_err(|_| invalid("lab lock failed"))?;
    lab.refresh()?;
    if matches!(command, "list" | "read" | "feed") {
        let mut cache = session
            .index
            .lock()
            .map_err(|_| invalid("index lock failed"))?;
        if cache
            .as_ref()
            .is_none_or(|index| index.ops != lab.len() || index.space != lab.space())
        {
            *cache = Some(ReadIndex {
                space: lab.space().into(),
                ops: lab.len(),
                graph: collab::Graph::load(&lab)?,
            });
        }
        return cache
            .as_ref()
            .expect("index loaded")
            .graph
            .query(command, args);
    }
    if matches!(
        command,
        "create" | "edit" | "integrate" | "checkpoint" | "run" | "replay"
    ) && !State::of(&lab)
        .roster
        .has(&session.who.submitter_id(), crate::lab::op::Role::Writer)
    {
        return Err(LabError::Refused(
            "this workbench identity is no longer a writer; edits and new runs are disabled".into(),
        ));
    }
    match command {
        "status" => {
            only(args, &[])?;
            let state = State::of(&lab);
            let (hardware, offer) = sample_offer(session);
            Ok(
                json!({"name":state.name,"space":lab.space(),"session":session.id,"directory":session.root,"author":session.who.submitter_id(),
                "environments":state.envs.keys().collect::<Vec<_>>(),"hardware":as_json(&hardware.to_value()),
                "environment_profiles":state.envs.iter().flat_map(|(name,versions)|versions.iter().map(move |env|json!({"name":name,"tree":env.tree}))).collect::<Vec<_>>(),
                "resources":as_json(&offer.to_value()),
                "runs":state.runs.iter().rev().take(30).map(|run|json!({"id":run.id,"author":run.author,"receipt":as_json(&run.receipt)})).collect::<Vec<_>>() }),
            )
        }
        "quote" => {
            only(
                args,
                &[
                    "workload",
                    "cpus",
                    "cpu_millis",
                    "memory_mb",
                    "duration_ms",
                    "cpu",
                ],
            )?;
            let request = crate::pricing::QuoteRequest::from_value(
                &Value::from_json(&args.to_string()).map_err(|e| invalid(&e.to_string()))?,
            )
            .map_err(|e| invalid(&e))?;
            let (_, offer) = sample_offer(session);
            crate::pricing::quote(&offer, &request)
                .map(|v| {
                    let mut quote = as_json(&v);
                    // A browser's Number cannot represent every u64 price. Keep
                    // the exact amount and canonical export alongside the JSON.
                    quote["amount_microunits_exact"] = json!(v
                        .get("amount_microunits")
                        .expect("quote amount")
                        .canonical_string());
                    quote["canonical_quote"] = json!(v.canonical_string());
                    quote
                })
                .map_err(LabError::Refused)
        }
        "run" => start_run(session, &mut lab, args),
        "replay" => start_replay(session, &mut lab, args),
        _ => collab::call(&mut lab, Some(&session.who), command, args),
    }
}

fn start_run(session: &Session, lab: &mut Lab, args: &Json) -> Result<Json, LabError> {
    only(
        args,
        &[
            "workspace",
            "heads",
            "env",
            "argv",
            "request",
            "timeout_seconds",
            "cpus",
            "memory_mb",
            "cpu",
            "workload",
            "recipe_of",
        ],
    )?;
    let id = text(args, "request")?;
    if id.is_empty() || id.len() > 128 {
        return Err(invalid("invalid run request id"));
    }
    let mut jobs = session
        .jobs
        .lock()
        .map_err(|_| invalid("job lock failed"))?;
    if let Some(job) = jobs.get(id) {
        if job.request != *args {
            return Err(LabError::Refused(
                "run request id already has different content".into(),
            ));
        }
        return Ok(json!({"job":id}));
    }
    if jobs.len() >= MAX_JOBS {
        return Err(LabError::Unavailable(
            "session run limit reached; inspect receipts and restart the workbench".into(),
        ));
    }
    if jobs.values().any(|job| job.result["state"] == "running") {
        return Err(LabError::Unavailable(
            "an experiment is running; wait for it to finish".into(),
        ));
    }
    let argv = args["argv"]
        .as_array()
        .filter(|v| !v.is_empty() && v.len() <= 64)
        .ok_or_else(|| invalid("argv needs 1..=64 strings"))?
        .iter()
        .map(|s| {
            s.as_str()
                .filter(|s| s.len() <= 8192 && !s.contains('\0'))
                .map(str::to_string)
                .ok_or_else(|| invalid("invalid argument"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let number = |key: &str, default, max| -> Result<u64, LabError> {
        let n = args
            .get(key)
            .map(|v| {
                v.as_u64()
                    .ok_or_else(|| invalid("limits must be whole numbers"))
            })
            .transpose()?
            .unwrap_or(default);
        if n == 0 || n > max {
            return Err(invalid("experiment limit is out of range"));
        }
        Ok(n)
    };
    let mut request = api::ExecRequest::new(text(args, "env")?, argv);
    let recipe = args
        .get("recipe_of")
        .map(|value| {
            let run = value
                .as_str()
                .ok_or_else(|| invalid("recipe_of must be a run id"))?;
            if !State::of(lab).runs.iter().any(|record| record.id == run) {
                return Err(LabError::NotFound(
                    "source recipe is not a recorded run in this lab".into(),
                ));
            }
            Ok(run)
        })
        .transpose()?;
    request.timeout = Duration::from_secs(number("timeout_seconds", 60, 600)?);
    request.cpus = number("cpus", 1, 64)? as u32;
    request.memory_mb = number("memory_mb", 1024, 262144)?;
    let requirements = args
        .get("cpu")
        .map(|value| {
            let value =
                Value::from_json(&value.to_string()).map_err(|e| invalid(&e.to_string()))?;
            crate::hardware::CpuRequirements::from_value(&value).map_err(|e| invalid(&e))
        })
        .transpose()?
        .unwrap_or_default();
    let (_, offer) = sample_offer(session);
    if !requirements.matches(offer.cpu.as_ref())
        || !offer
            .cpus
            .is_some_and(|cpus| cpus >= u64::from(request.cpus))
        || !offer
            .cpu_millis
            .is_some_and(|quota| quota >= u64::from(request.cpus) * 1000)
        || !offer
            .memory_mb
            .is_some_and(|memory| memory >= request.memory_mb)
    {
        return Err(LabError::Unavailable("this machine cannot confirm the requested CPU/ISA/memory allocation; lower the allocation or use a compatible host".into()));
    }
    let estimate = if let Some(workload) = args.get("workload") {
        let workload = workload
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| invalid("workload must be non-empty"))?;
        Some(as_json(
            &crate::pricing::quote(
                &offer,
                &crate::pricing::QuoteRequest {
                    workload: workload.into(),
                    cpu_millis: u64::from(request.cpus) * 1000,
                    memory_mb: request.memory_mb,
                    duration_ms: request.timeout.as_millis() as u64,
                    cpu: requirements.clone(),
                },
            )
            .map_err(LabError::Refused)?,
        ))
    } else {
        None
    };
    request.pids = 128;
    request.tmp_mb = 256;
    request.cwd = Some("/src".into());
    request.note = Some(json!({"workbench_request":id,"recipe_of":recipe,"requirements":as_json(&requirements.to_value()),"cpu":offer.cpu.as_ref().map(|cpu|as_json(&cpu.to_value())),"estimate":estimate}).to_string());
    // Check before pinning inputs; Auto never falls back to an unconfined run.
    exec::backend(exec::Preference::Auto)?;
    let checkpoint = collab::call(
        lab,
        Some(&session.who),
        "checkpoint",
        &json!({"workspace":args["workspace"],"heads":args["heads"]}),
    )?;
    request.inputs = checkpoint["inputs"]
        .as_array()
        .expect("checkpoint inputs")
        .iter()
        .map(|i| api::Input {
            prefix: i["prefix"].as_str().expect("prefix").into(),
            target: i["target"].as_str().expect("target").into(),
        })
        .collect();
    jobs.insert(
        id.into(),
        Job {
            request: args.clone(),
            result: json!({"state":"running","checkpoint":checkpoint,"estimate":estimate}),
        },
    );
    let root = session.root.clone();
    let who = session.who.clone();
    let jobs = Arc::clone(&session.jobs);
    let id = id.to_string();
    let response = json!({"job":id});
    std::thread::spawn(move || {
        let result = Lab::open(&root).and_then(|mut lab| api::exec(&mut lab, &who, &request));
        let value = match result {
            Ok(run) => {
                json!({"state":if run.outcome.error.is_some(){"unavailable"}else{"complete"},"error":run.outcome.error,"run":run.op.id,"receipt":match &run.op.body { crate::lab::op::Body::Run{receipt,..} => as_json(receipt), _ => Json::Null },
                "stdout":preview(&run.stdout),"stderr":preview(&run.stderr),"checkpoint":checkpoint,"estimate":estimate})
            }
            Err(error) => {
                json!({"state":"unavailable","error":error.to_string(),"checkpoint":checkpoint})
            }
        };
        if let Ok(mut jobs) = jobs.lock() {
            if let Some(job) = jobs.get_mut(&id) {
                job.result = value;
            }
        }
    });
    Ok(response)
}

fn preview(text: &str) -> String {
    let mut end = text.len().min(16_384);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    if end == text.len() {
        text.into()
    } else {
        format!(
            "{}\n[preview truncated; full streams are pinned in the receipt]",
            &text[..end]
        )
    }
}

fn start_replay(session: &Session, lab: &mut Lab, args: &Json) -> Result<Json, LabError> {
    only(args, &["run", "request"])?;
    let id = text(args, "request")?;
    let run = text(args, "run")?;
    if id.is_empty() || id.len() > 128 {
        return Err(invalid("invalid replay request id"));
    }
    let mut jobs = session
        .jobs
        .lock()
        .map_err(|_| invalid("job lock failed"))?;
    if let Some(job) = jobs.get(id) {
        if job.request != *args {
            return Err(LabError::Refused(
                "request id already has different content".into(),
            ));
        }
        return Ok(json!({"job":id}));
    }
    if jobs.len() >= MAX_JOBS || jobs.values().any(|job| job.result["state"] == "running") {
        return Err(LabError::Unavailable(
            "a run is active or this session reached its run limit".into(),
        ));
    }
    let plan = crate::lab::replay::plan(lab, run, crate::lab::replay::Mode::Exact)?;
    let request = &plan.request;
    if request.network
        || request.timeout.as_secs() > 600
        || request.cpus == 0
        || request.cpus > 64
        || request.memory_mb == 0
        || request.memory_mb > 262144
        || request.pids == 0
        || request.pids > 128
        || request.tmp_mb > 256
    {
        return Err(LabError::Refused("this recipe exceeds the local GUI's isolation or resource limits; review it with the CLI, or use its command as a new bounded experiment".into()));
    }
    let (_, offer) = sample_offer(session);
    if !offer
        .cpus
        .is_some_and(|cpus| cpus >= u64::from(request.cpus))
        || !offer
            .cpu_millis
            .is_some_and(|quota| quota >= u64::from(request.cpus) * 1000)
        || !offer
            .memory_mb
            .is_some_and(|memory| memory >= request.memory_mb)
    {
        return Err(LabError::Unavailable(
            "this host cannot confirm the recorded allocation".into(),
        ));
    }
    exec::backend(exec::Preference::Auto)?;
    jobs.insert(
        id.into(),
        Job {
            request: args.clone(),
            result: json!({"state":"running","replay_of":run}),
        },
    );
    let id = id.to_string();
    let run = run.to_string();
    let root = session.root.clone();
    let who = session.who.clone();
    let jobs = Arc::clone(&session.jobs);
    let response = json!({"job":id});
    std::thread::spawn(move || {
        let result = Lab::open(&root).and_then(|mut lab| {
            api::replay(
                &mut lab,
                &who,
                &run,
                crate::lab::replay::Mode::Exact,
                None,
                exec::Preference::Auto,
                None,
            )
        });
        let value = match result {
            Ok(result) => {
                json!({"state":if result.outcome.error.is_some(){"unavailable"}else{"complete"},"error":result.outcome.error,"run":result.op.id,"replay_of":run,
                "stdout":preview(&result.stdout),"stderr":preview(&result.stderr)})
            }
            Err(error) => json!({"state":"unavailable","error":error.to_string(),"replay_of":run}),
        };
        if let Ok(mut jobs) = jobs.lock() {
            if let Some(job) = jobs.get_mut(&id) {
                job.result = value;
            }
        }
    });
    Ok(response)
}

fn sample_offer(session: &Session) -> (crate::network::Hardware, crate::scheduling::ResourceOffer) {
    let hardware = crate::network::Hardware::probe();
    let mut offer =
        super::resource_offer_from_env(&hardware).unwrap_or(crate::scheduling::ResourceOffer {
            cpus: hardware.cpus,
            memory_mb: hardware.memory_mb,
            cpu_millis: hardware
                .cpu_millis
                .or_else(|| hardware.cpus.and_then(|cpus| cpus.checked_mul(1000))),
            cpu: Some(hardware.cpu.clone()),
            concurrency: Some(1),
            gpus: None,
            storage_mb: None,
            pricing: None,
        });
    offer.pricing = session
        .offer
        .as_ref()
        .and_then(|offer| offer.pricing.clone());
    (hardware, offer)
}
fn as_json(value: &Value) -> Json {
    serde_json::from_str(&value.canonical_string()).expect("canonical JSON")
}
fn invalid(message: &str) -> LabError {
    LabError::Invalid(message.into())
}
fn text<'a>(value: &'a Json, key: &str) -> Result<&'a str, LabError> {
    value[key]
        .as_str()
        .ok_or_else(|| invalid(&format!("{key} must be a string")))
}
fn only(value: &Json, fields: &[&str]) -> Result<(), LabError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("expected an object"))?;
    if object.keys().any(|key| !fields.contains(&key.as_str())) {
        return Err(invalid("unknown request field"));
    }
    Ok(())
}
fn error_response(stream: &mut TcpStream, status: u16, error: &str, kind: &str) -> io::Result<()> {
    answer(
        stream,
        status,
        "application/json",
        json!({"error":error,"kind":kind}).to_string().as_bytes(),
    )
}
fn answer(stream: &mut TcpStream, status: u16, mime: &str, bytes: &[u8]) -> io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        415 => "Unsupported Media Type",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    };
    write!(stream,"HTTP/1.1 {status} {reason}\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nCross-Origin-Resource-Policy: same-origin\r\nContent-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'\r\n\r\n",bytes.len())?;
    stream.write_all(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lab::op::Policy;
    use std::io::Read as _;

    struct Fixture {
        root: PathBuf,
        session: Arc<Session>,
    }
    impl Fixture {
        fn new() -> Self {
            let root =
                std::env::temp_dir().join(format!("cairn-web-{}", collab::request_id().unwrap()));
            let who = Identity::from_secret_bytes([47; 32]);
            let lab = Lab::init(
                &root,
                &who,
                "Local",
                Vec::new(),
                Policy {
                    write_once: vec!["checkpoints/**".into()],
                    ..Policy::default()
                },
            )
            .unwrap();
            Self {
                root: root.clone(),
                session: Arc::new(Session {
                    id: "test-session".into(),
                    lab: Mutex::new(lab),
                    root,
                    who,
                    token: Ok(Some(
                        super::super::operator::Token::parse(&"ab".repeat(32)).unwrap(),
                    )),
                    authority: String::new(),
                    jobs: Arc::new(Mutex::new(BTreeMap::new())),
                    offer: None,
                    index: Mutex::new(None),
                }),
            }
        }
        fn ask(&mut self, build: impl FnOnce(&str) -> String) -> String {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let authority = listener.local_addr().unwrap().to_string();
            Arc::get_mut(&mut self.session).unwrap().authority = authority.clone();
            let session = Arc::clone(&self.session);
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                handle(&mut stream, &session).unwrap();
            });
            let mut client = TcpStream::connect(&authority).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            client.write_all(build(&authority).as_bytes()).unwrap();
            client.shutdown(std::net::Shutdown::Write).unwrap();
            let mut response = String::new();
            client.read_to_string(&mut response).unwrap();
            server.join().unwrap();
            response
        }
        fn post(&mut self, value: Json) -> Json {
            let response=self.ask(|host|format!("POST /api HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{value}","ab".repeat(32),value.to_string().len()));
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
            serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn local_control_refuses_missing_credentials_rebinding_foreign_origins_and_proxies() {
        let mut f = Fixture::new();
        let body = r#"{"command":"list","args":{}}"#;
        for (extra, expected) in [
            ("", 401),
            ("Origin: https://evil.example\r\n", 403),
            ("Forwarded: for=127.0.0.1\r\n", 403),
            ("X-Forwarded-Host: example.test\r\n", 403),
        ] {
            let response=f.ask(|host|format!("POST /api HTTP/1.1\r\nHost: {host}\r\n{extra}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",body.len()));
            assert!(
                response.starts_with(&format!("HTTP/1.1 {expected}")),
                "{response}"
            );
        }
        let response = f.ask(|_| "GET / HTTP/1.1\r\nHost: rebound.example\r\n\r\n".into());
        assert!(response.starts_with("HTTP/1.1 403"));
        let response = f.ask(|host| format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n"));
        assert!(response.contains("Content-Security-Policy: default-src 'none'"));
        assert!(response.contains("frame-ancestors 'none'"));
        assert!(!response.contains("Access-Control-Allow-Origin"));
        assert!(!response.contains(&"ab".repeat(32)));
    }

    #[test]
    fn ambiguous_framing_is_rejected_before_reading_or_authorizing_a_body() {
        let mut f = Fixture::new();
        for headers in [
            "Content-Length: 2\r\nContent-Length: 2\r\n",
            "Transfer-Encoding: chunked\r\n",
            "Content-Length: 999999999\r\n",
            "Origin: http://a\r\nOrigin: http://b\r\n",
            "Authorization: Bearer a\r\nAuthorization: Bearer b\r\n",
        ] {
            let response =
                f.ask(|host| format!("POST /api HTTP/1.1\r\nHost: {host}\r\n{headers}\r\n"));
            assert!(response.starts_with("HTTP/1.1 400"), "{response}");
        }
    }

    #[test]
    fn authenticated_edits_share_validation_and_retry_semantics_with_cli_and_mcp() {
        let mut f = Fixture::new();
        let created = f.post(
            json!({"command":"create","args":{"title":"Browser <script>","request":"create"}}),
        );
        let workspace = created["workspace"].as_str().unwrap();
        let edit = json!({"command":"edit","args":{"workspace":workspace,"heads":created["heads"],"request":"edit",
            "edits":[{"path":"algorithm.py","start":0,"delete":0,"insert":"🦀 + λ","executable":false}]}});
        assert_eq!(f.post(edit.clone()), f.post(edit));
        let read = f.post(json!({"command":"read","args":{"workspace":workspace}}));
        assert_eq!(read["contents"]["algorithm.py"], "🦀 + λ");
        let lab = f.session.lab.lock().unwrap();
        assert_eq!(lab.len(), 3);
        assert!(lab
            .ops()
            .iter()
            .all(|op| crate::lab::op::Op::from_line(&op.to_line()).is_ok()));
    }

    #[test]
    fn public_interfaces_never_gain_an_edit_route_or_an_unconfined_execution_option() {
        let f = Fixture::new();
        assert!(call(
            &f.session,
            &json!({"command":"quote","args":{"host":"another-machine"}})
        )
        .is_err());
        assert!(call(
            &f.session,
            &json!({"command":"run","args":{"sandbox":"none"}})
        )
        .is_err());
        assert!(
            Workbench::bind(&f.root, f.session.who.clone(), "0.0.0.0:0".parse().unwrap()).is_err()
        );
        assert!(call(
            &f.session,
            &json!({"command":"checkout","args":{"target":"/tmp/unexpected"}})
        )
        .is_err());
    }

    #[test]
    fn cached_reads_invalidate_for_membership_revocation_as_well_as_source_edits() {
        let f = Fixture::new();
        let writer = Identity::from_secret_bytes([48; 32]);
        let workspace;
        let revocation;
        {
            let mut lab = f.session.lab.lock().unwrap();
            lab.append(
                &f.session.who,
                crate::lab::op::Body::Members {
                    admit: vec![crate::lab::op::Member {
                        key: writer.submitter_id(),
                        roles: [crate::lab::op::Role::Writer].into_iter().collect(),
                        peers: Default::default(),
                    }],
                    revoke: Vec::new(),
                },
            )
            .unwrap();
            workspace = collab::create(
                &mut lab,
                &f.session.who,
                "Cached",
                &Default::default(),
                "create",
            )
            .unwrap();
            let replica = f.root.join("revocation-replica");
            Lab::create_empty(&replica, lab.space()).unwrap();
            let mut admin = Lab::open(&replica).unwrap();
            let (_, refused) = admin.ingest_many(lab.ops().to_vec()).unwrap();
            assert!(refused.is_empty());
            revocation = admin
                .append(
                    &f.session.who,
                    crate::lab::op::Body::Members {
                        admit: Vec::new(),
                        revoke: vec![writer.submitter_id()],
                    },
                )
                .unwrap();
            collab::edit(
                &mut lab,
                &writer,
                &workspace,
                &[workspace.clone()].into_iter().collect(),
                &[collab::Edit::splice("work.py", 0, 0, "signed by writer")],
                "writer-edit",
            )
            .unwrap();
        }
        let request = json!({"command":"read","args":{"workspace":workspace}});
        assert_eq!(
            call(&f.session, &request).unwrap()["contents"]["work.py"],
            "signed by writer"
        );
        {
            let mut lab = f.session.lab.lock().unwrap();
            lab.ingest(revocation).unwrap();
        }
        assert!(call(&f.session, &request).unwrap()["contents"]
            .as_object()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn an_open_session_cannot_start_writes_or_runs_after_its_writer_role_is_removed() {
        let f = Fixture::new();
        {
            let mut lab = f.session.lab.lock().unwrap();
            lab.append(
                &f.session.who,
                crate::lab::op::Body::Members {
                    admit: vec![crate::lab::op::Member {
                        key: f.session.who.submitter_id(),
                        roles: [crate::lab::op::Role::Admin, crate::lab::op::Role::Reader]
                            .into_iter()
                            .collect(),
                        peers: Default::default(),
                    }],
                    revoke: Vec::new(),
                },
            )
            .unwrap();
        }
        for command in ["create", "edit", "integrate", "checkpoint", "run", "replay"] {
            assert!(matches!(
                call(&f.session, &json!({"command":command,"args":{}})),
                Err(LabError::Refused(_))
            ));
        }
        assert!(call(&f.session, &json!({"command":"list","args":{}})).is_ok());
    }
}
