// DOMAIN-001a: pure debounce state machine for the publish scheduler.
//
// This is the pure state machine (part a). The background loop, Arc sharing,
// config wiring and handler wiring belong to other parts of DOMAIN-001 and are
// out of scope here. The state machine is pure: it takes the current time
// (seconds) as an argument and returns an Action.

/// What a `tick` decides to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Nothing to publish right now.
    None,
    /// Publish now (the caller runs `publish::publish` and then calls
    /// `on_started` / `on_finished`).
    Publish,
}

impl Action {
    /// True when this tick wants a publish.
    pub fn is_publish(&self) -> bool { todo!() }
}

/// Backoff schedule for failed publishes: 30 s, 60 s, 120 s, capped at 300 s.
const BACKOFF_SECS: [u64; 3] = [30, 60, 120];
const MAX_BACKOFF_SECS: u64 = 300;

/// Pure debounce state machine.
///
/// Turns "something changed" requests into at most one publish after
/// `debounce_secs` of quiet, one at a time, with retry on failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishScheduler {
    debounce_secs: u64,
    auto: bool,
    /// Last time a request arrived.
    last_request: Option<u64>,
    /// A request is waiting to be published.
    pending: bool,
    /// A publish is currently running.
    running: bool,
    /// Earliest time a retry may run (0 until a failure sets it).
    next_retry: u64,
    /// Number of consecutive failures, indexing into `BACKOFF_SECS`.
    failures: u32,
}

impl Default for PublishScheduler {
    fn default() -> Self {
        Self {
            // Defaults per DOMAIN-001a: debounce 60 s, auto on, idle.
            debounce_secs: 60,
            auto: true,
            last_request: None,
            pending: false,
            running: false,
            next_retry: 0,
            failures: 0,
        }
    }
}

impl PublishScheduler {
    /// Build a scheduler with the given debounce and auto settings.
    pub fn new(debounce_secs: u64, auto: bool) -> Self { todo!() }

    /// Record a "something changed" request at `now`.
    pub fn on_request(&mut self, now: u64) { todo!() }

    /// Decide whether to publish now. Pure: takes the current time as input.
    pub fn tick(&mut self, now: u64) -> Action { todo!() }

    /// Mark a publish as started.
    pub fn on_started(&mut self) { todo!() }

    /// Mark a publish as finished with outcome `ok` at time `now`.
    pub fn on_finished(&mut self, now: u64, ok: bool) { todo!() }
}

use std::sync::Arc;

impl PublishScheduler {
    /// Cheap handle shared with handlers; records a request.
    pub fn request(&self, _reason: &str) {
        todo!()
    }

    /// Background loop: call `tick` every second and publish when due.
    pub async fn run(self, _config: (), _secrets: (), _pool: ()) {
        todo!()
    }
}
