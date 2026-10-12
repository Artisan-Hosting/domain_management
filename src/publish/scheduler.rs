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
    pub fn is_publish(&self) -> bool {
        matches!(self, Action::Publish)
    }
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
    pub fn new(debounce_secs: u64, auto: bool) -> Self {
        Self {
            debounce_secs,
            auto,
            ..Default::default()
        }
    }

    /// Record a "something changed" request at `now`.
    pub fn on_request(&mut self, now: u64) {
        self.last_request = Some(now);
        self.pending = true;
    }

    /// Decide whether to publish now. Pure: takes the current time as input.
    pub fn tick(&mut self, now: u64) -> Action {
        if !self.auto || self.running {
            return Action::None;
        }
        let pending = match self.last_request {
            Some(last) => self.pending && now - last >= self.debounce_secs && now >= self.next_retry,
            None => false,
        };
        if pending {
            // Coalesce the burst into one publish: clear `pending` here so a
            // request that arrives during this publish yields exactly one more.
            self.pending = false;
            Action::Publish
        } else {
            Action::None
        }
    }

    /// Mark a publish as started.
    pub fn on_started(&mut self) {
        self.running = true;
    }

    /// Mark a publish as finished with outcome `ok` at time `now`.
    pub fn on_finished(&mut self, now: u64, ok: bool) {
        self.running = false;
        if ok {
            // A request that arrived during the publish is coalesced into one
            // more publish after a fresh debounce window from when it finished.
            self.last_request = Some(now);
            self.failures = 0;
            self.next_retry = 0;
        } else {
            let backoff = *BACKOFF_SECS.get(self.failures as usize)
                .unwrap_or(&MAX_BACKOFF_SECS);
            self.next_retry = now.saturating_add(backoff.min(MAX_BACKOFF_SECS));
            self.failures += 1;
        }
    }
}

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
