//! What this process did, as a short feed a person can read.
//!
//! The log says what was *admitted*: objectives, commitments, claims,
//! verdicts, payments. It says nothing about the node doing its job -- that it
//! reached a peer and pulled twelve records from it, that a machine started
//! heartbeating, that an agent attached over MCP. Those lines existed only on
//! stderr (`log::info!`), which an operator reading the node through its own
//! window never sees, and which is narrated for a developer rather than for
//! them: every five-second session, every beacon, in the daemon's words.
//!
//! This is the other half: a bounded ring of **changes**, said once. A peer is
//! announced when it is first reached and when it comes back after being lost,
//! not on every session; a worker when it starts on an objective, not on every
//! heartbeat. `GET /events` serves it, and the reader's Log page interleaves it
//! with the records.
//!
//! # What it is not
//!
//! **Not a record.** Never appended, never gossiped, gone on restart -- the
//! same standing as a heartbeat or a session row, and for the same reason: it
//! is this process's memory of what it saw, and two nodes' journals are two
//! processes' memories. Nothing that pays, settles or audits reads it.
//!
//! **Not evidence.** An event saying a worker started is the worker's own
//! heartbeat, restated; one saying an agent posted an objective is this
//! process's account of its own MCP session. Where the log has the fact, the
//! log is the authority and this is a convenience pointing at it.
//!
//! # Why it is passed around rather than global
//!
//! Three threads write here -- the p2p loops, the HTTP handlers and the MCP
//! session -- and a `static` would have been the shortest way to reach all of
//! them. It would also have made every unit test in the crate write into one
//! shared feed, and a test asserting what a route reports would be asserting
//! about whatever ran beside it. So the daemon makes one [`Shared`] and hands
//! it to each half, exactly as it already hands them the session roster.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use crate::canonical::Value;
use crate::time::format_iso8601_utc;

/// Most events held. Old ones fall off the front: a node up for a month
/// should not carry a month of "worker started" in memory, and a reader
/// wanting more than the recent past wants the log, not this.
pub const CAPACITY: usize = 500;

/// Most events one `GET /events` returns.
pub const MAX_PAGE: usize = 200;

/// Longest text kept per event, in characters. Some of it is a peer's to shape
/// -- a transport error, a client's name for itself -- and a feed is not a
/// place to store whatever a stranger sends.
pub const MAX_TEXT: usize = 240;

/// What an event is about, for the reader's filter and icon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// This process: started, serving, a decision it made about itself.
    Node,
    /// Another node: reached, back, unreachable, records synced.
    Peer,
    /// A machine heartbeating on an objective.
    Worker,
    /// A machine registering its hardware with `cairn agent`.
    Host,
    /// A worker's advisory task lease.
    Lease,
    /// A fleet member enrolling.
    Fleet,
    /// Something proposed over HTTP and queued for admission.
    Submission,
    /// An agent attached over MCP, and what it wrote.
    Agent,
}

impl Kind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Kind::Node => "node",
            Kind::Peer => "peer",
            Kind::Worker => "worker",
            Kind::Host => "host",
            Kind::Lease => "lease",
            Kind::Fleet => "fleet",
            Kind::Submission => "submission",
            Kind::Agent => "agent",
        }
    }
}

/// How a reader should colour it. The same four tones the Log page gives a
/// record, so an unreachable peer and a rejected claim look alike for being
/// alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Neutral,
    Good,
    Warn,
    Bad,
}

impl Tone {
    pub const fn as_str(self) -> &'static str {
        match self {
            Tone::Neutral => "neutral",
            Tone::Good => "good",
            Tone::Warn => "warn",
            Tone::Bad => "bad",
        }
    }
}

/// One thing that happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// Strictly increasing within a process, from 1, so a reader can ask for
    /// what came after the last one it saw. Restarts at 1 with the process;
    /// [`Journal::to_value`] publishes `started_at` so a reader can tell.
    pub seq: u64,
    /// Unix seconds, by this process's clock. Display only -- nothing here is
    /// an epoch, and nothing derives one from it.
    pub at: u64,
    pub kind: Kind,
    pub tone: Tone,
    /// One sentence, already in a reader's words.
    pub text: String,
    /// What it is about, for a link or a search: a peer id, an objective id,
    /// a worker or host name. Never an amount.
    pub subject: Option<String>,
}

impl Event {
    pub fn to_value(&self) -> Value {
        let at = i64::try_from(self.at).unwrap_or(i64::MAX);
        Value::object([
            ("seq", Value::Int(i128::from(self.seq))),
            ("at", Value::string(format_iso8601_utc(at))),
            ("kind", Value::string(self.kind.as_str())),
            ("tone", Value::string(self.tone.as_str())),
            ("text", Value::string(self.text.clone())),
            (
                "subject",
                match &self.subject {
                    Some(subject) => Value::string(subject.clone()),
                    None => Value::Null,
                },
            ),
        ])
    }
}

/// The ring. See the module docs.
#[derive(Debug)]
pub struct Journal {
    events: VecDeque<Event>,
    next: u64,
    started_at: u64,
}

/// The one journal a process's halves share.
pub type Shared = Arc<Mutex<Journal>>;

impl Journal {
    pub fn new(now: u64) -> Journal {
        Journal {
            events: VecDeque::new(),
            next: 1,
            started_at: now,
        }
    }

    pub fn shared(now: u64) -> Shared {
        Arc::new(Mutex::new(Journal::new(now)))
    }

    /// Add an event and return its `seq`.
    pub fn push(
        &mut self,
        at: u64,
        kind: Kind,
        tone: Tone,
        text: &str,
        subject: Option<&str>,
    ) -> u64 {
        let seq = self.next;
        self.next += 1;
        self.events.push_back(Event {
            seq,
            at,
            kind,
            tone,
            text: clip(text),
            subject: subject.map(clip),
        });
        while self.events.len() > CAPACITY {
            self.events.pop_front();
        }
        seq
    }

    /// The newest `limit` events with `seq > after`, oldest first. Newest
    /// rather than oldest when there are more than `limit`: a reader that fell
    /// a long way behind wants to see now, and the gap is reported as
    /// `dropped` rather than paged through.
    pub fn after(&self, after: u64, limit: usize) -> Vec<&Event> {
        let fresh: Vec<&Event> = self.events.iter().filter(|e| e.seq > after).collect();
        let skip = fresh.len().saturating_sub(limit);
        fresh.into_iter().skip(skip).collect()
    }

    /// `GET /events?after=<seq>`.
    pub fn to_value(&self, after: u64, limit: usize) -> Value {
        let limit = limit.clamp(1, MAX_PAGE);
        let events = self.after(after, limit);
        // Events the reader asked for and will not get: fallen off the ring,
        // or past this page. Said, so a feed with a hole in it says so.
        let oldest = self.events.front().map_or(self.next, |e| e.seq);
        let fallen = oldest.saturating_sub(after.saturating_add(1));
        let unpaged = self.events.iter().filter(|e| e.seq > after).count() - events.len();
        let started = i64::try_from(self.started_at).unwrap_or(i64::MAX);
        Value::object([
            (
                "events",
                Value::array(events.iter().map(|event| event.to_value())),
            ),
            ("last", Value::Int(i128::from(self.next - 1))),
            ("dropped", Value::Int(i128::from(fallen) + unpaged as i128)),
            ("capacity", Value::Int(CAPACITY as i128)),
            ("started_at", Value::string(format_iso8601_utc(started))),
            (
                "note",
                Value::string(
                    "What this process saw happen -- peers reached and lost, records synced, \
                     machines and agents arriving -- said once per change, newest last. Held \
                     in memory and gone on restart; never a record, never evidence, and \
                     nothing that pays reads it. `after` is the last `seq` you have.",
                ),
            ),
        ])
    }
}

/// Add an event to a shared journal, stamped now. A poisoned lock still
/// takes it: a panic in some other handler is no reason to stop narrating.
pub fn note(journal: &Shared, kind: Kind, tone: Tone, text: &str, subject: Option<&str>) {
    journal
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(crate::time::unix_seconds(), kind, tone, text, subject);
}

fn clip(text: &str) -> String {
    let mut out: String = text
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_TEXT)
        .collect();
    if text.chars().count() > MAX_TEXT {
        out.push('…');
    }
    out
}

/// `3f2a9c1d…`, for a peer id or a key in a sentence. The whole value goes in
/// `subject`, where a reader can copy it.
pub fn short(id: &str) -> String {
    let bare = id.strip_prefix("sha256:").unwrap_or(id);
    if bare.chars().count() <= 12 {
        bare.to_string()
    } else {
        format!("{}…", bare.chars().take(8).collect::<String>())
    }
}

/// `4 min`, `2 h`, `3 d` -- how long a peer was gone, in a sentence.
pub fn span(seconds: u64) -> String {
    match seconds {
        s if s < 90 => format!("{s} s"),
        s if s < 90 * 60 => format!("{} min", s / 60),
        s if s < 36 * 3600 => format!("{} h", s / 3600),
        s => format!("{} d", s / 86_400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_are_numbered_from_one_and_paged_after_a_seq() {
        let mut journal = Journal::new(100);
        assert_eq!(
            journal.push(101, Kind::Node, Tone::Good, "started", None),
            1
        );
        assert_eq!(
            journal.push(102, Kind::Peer, Tone::Good, "reached", Some("abc")),
            2
        );
        assert_eq!(journal.after(0, 10).len(), 2);
        let fresh = journal.after(1, 10);
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].text, "reached");
        assert!(journal.after(2, 10).is_empty());
    }

    #[test]
    fn the_ring_is_bounded_and_says_what_fell_off() {
        let mut journal = Journal::new(0);
        for n in 0..(CAPACITY as u64 + 25) {
            journal.push(n, Kind::Worker, Tone::Neutral, "w", None);
        }
        assert_eq!(journal.events.len(), CAPACITY);
        let page = journal.to_value(0, MAX_PAGE);
        // 25 fell off the front, and the page holds the newest MAX_PAGE of
        // the CAPACITY still here, so the rest of those are unpaged.
        let dropped = page.get("dropped").and_then(Value::as_u64).unwrap();
        assert_eq!(dropped, 25 + (CAPACITY - MAX_PAGE) as u64);
        let events = page.get("events").and_then(Value::as_array).unwrap();
        assert_eq!(events.len(), MAX_PAGE);
        // Newest last, and the newest is the last pushed.
        let last = events
            .last()
            .and_then(|e| e.get("seq"))
            .and_then(Value::as_u64);
        assert_eq!(last, Some(CAPACITY as u64 + 25));
    }

    #[test]
    fn a_reader_that_is_caught_up_gets_nothing_and_no_hole() {
        let mut journal = Journal::new(0);
        journal.push(1, Kind::Node, Tone::Good, "a", None);
        let page = journal.to_value(1, 50);
        assert_eq!(
            page.get("events")
                .and_then(Value::as_array)
                .map(<[Value]>::len),
            Some(0)
        );
        assert_eq!(page.get("dropped").and_then(Value::as_u64), Some(0));
        assert_eq!(page.get("last").and_then(Value::as_u64), Some(1));
    }

    #[test]
    fn text_a_stranger_shaped_is_clipped_and_stripped_of_control_characters() {
        let mut journal = Journal::new(0);
        let long = format!("evil\u{1b}[2J{}", "x".repeat(MAX_TEXT * 2));
        journal.push(0, Kind::Peer, Tone::Bad, &long, Some("id\nwith newline"));
        let event = &journal.events[0];
        assert!(!event.text.contains('\u{1b}'));
        assert!(event.text.chars().count() <= MAX_TEXT + 1);
        assert!(event.text.ends_with('…'));
        assert_eq!(event.subject.as_deref(), Some("idwith newline"));
    }

    #[test]
    fn short_ids_and_spans_read_as_words() {
        assert_eq!(short("sha256:0123456789abcdef0123"), "01234567…");
        assert_eq!(short("garage-gpu"), "garage-gpu");
        assert_eq!(span(30), "30 s");
        assert_eq!(span(600), "10 min");
        assert_eq!(span(7200), "2 h");
        assert_eq!(span(3 * 86_400), "3 d");
    }
}
