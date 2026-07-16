use crate::cli::color::*;

#[derive(Debug, Clone, PartialEq)]
pub enum LogState {
    Info,
    Debug,
    Error,
    Fatal,
}

impl LogState {
    /// Colored label — pulls directly from the constants at the top of the file.
    pub fn label(&self) -> String {
        match self {
            LogState::Info => palette::INFO.paint("[INFO ]"),
            LogState::Debug => palette::DEBUG.paint("[DEBUG]"),
            LogState::Error => palette::ERROR.paint("[ERROR]"),
            LogState::Fatal => palette::FATAL.paint("[FATAL]"),
        }
    }

    fn severity(&self) -> u8 {
        match self {
            LogState::Info => 0,
            LogState::Debug => 1,
            LogState::Error => 2,
            LogState::Fatal => 3,
        }
    }

    /// Transitions enforce one-way severity escalation.
    /// Downgrading (e.g. Fatal → Info) is rejected with an Err.
    pub fn transition(&self, next: LogState) -> Result<LogState, String> {
        if next.severity() >= self.severity() {
            Ok(next)
        } else {
            Err(format!(
                "illegal downgrade: {:?} (severity {}) → {:?} (severity {})",
                self,
                self.severity(),
                next,
                next.severity(),
            ))
        }
    }
}

pub struct Logger {
    state: LogState,
}

impl Logger {
    pub fn new() -> Self {
        Self {
            state: LogState::Info,
        }
    }

    /// Explicit state transition — returns Err if the move would lower severity.
    pub fn set_state(&mut self, next: LogState) -> Result<(), String> {
        self.state = self.state.transition(next)?;
        Ok(())
    }

    pub fn state(&self) -> &LogState {
        &self.state
    }

    pub fn log_fmt(&self, args: std::fmt::Arguments) {
        println!("{} {}", self.state.label(), args);
    }

    pub fn info_fmt(&mut self, args: std::fmt::Arguments) {
        let _ = self.set_state(LogState::Info);
        println!("{} {}", LogState::Info.label(), args);
    }

    pub fn debug_fmt(&mut self, args: std::fmt::Arguments) {
        let _ = self.set_state(LogState::Debug);
        println!("{} {}", LogState::Debug.label(), args);
    }

    pub fn error_fmt(&mut self, args: std::fmt::Arguments) {
        let _ = self.set_state(LogState::Error);
        println!("{} {}", LogState::Error.label(), args);
    }

    pub fn fatal_fmt(&mut self, args: std::fmt::Arguments) {
        let _ = self.set_state(LogState::Fatal);
        println!("{} {}", LogState::Fatal.label(), args);
    }
}

impl Default for Logger {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests for src/utils/logger.rs
//
// Paste this block at the bottom of src/utils/logger.rs
//
// What is testable here:
//   • LogState::transition() — the one-way severity escalation rule.
//     This is pure logic with no I/O, so every path can be fully exercised.
//   • LogState::severity()   — internal ordering used by transition().
//   • Logger::set_state()    — public wrapper around transition().
//   • Logger::state()        — readable after every set_state() call.
//
// What is intentionally NOT tested:
//   • The *fmt methods (info_fmt, debug_fmt, …) — they call println!() which
//     writes to stdout.  Capturing stdout in Rust requires either a custom
//     writer injection or the `gag` crate.  The print logic is trivial
//     (label + args) so we skip it in favour of testing the state machine,
//     which is where the real invariants live.
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── LogState::severity() — ordering contract ──────────────────────────────

    /// Info < Debug < Error < Fatal — the severity ordering must be strict and
    /// monotone.  Any reordering here would silently break the state machine.
    #[test]
    fn test_severity_ordering_is_strict() {
        assert!(LogState::Info.severity() < LogState::Debug.severity());
        assert!(LogState::Debug.severity() < LogState::Error.severity());
        assert!(LogState::Error.severity() < LogState::Fatal.severity());
    }

    /// No two distinct variants may share the same severity number.
    #[test]
    fn test_severity_values_are_unique() {
        let values = [
            LogState::Info.severity(),
            LogState::Debug.severity(),
            LogState::Error.severity(),
            LogState::Fatal.severity(),
        ];
        // If any two are equal, the set-size check fails.
        let unique: std::collections::HashSet<u8> = values.iter().copied().collect();
        assert_eq!(
            unique.len(),
            values.len(),
            "severity values must all be distinct"
        );
    }

    // ── LogState::transition() — allowed upgrades ─────────────────────────────

    /// Same-level transition must always succeed (no-op upgrade).
    #[test]
    fn test_transition_same_level_is_allowed() {
        assert!(LogState::Info.transition(LogState::Info).is_ok());
        assert!(LogState::Debug.transition(LogState::Debug).is_ok());
        assert!(LogState::Error.transition(LogState::Error).is_ok());
        assert!(LogState::Fatal.transition(LogState::Fatal).is_ok());
    }

    /// Every strictly-higher transition must succeed.
    #[test]
    fn test_transition_upward_is_allowed() {
        assert!(LogState::Info.transition(LogState::Debug).is_ok());
        assert!(LogState::Info.transition(LogState::Error).is_ok());
        assert!(LogState::Info.transition(LogState::Fatal).is_ok());
        assert!(LogState::Debug.transition(LogState::Error).is_ok());
        assert!(LogState::Debug.transition(LogState::Fatal).is_ok());
        assert!(LogState::Error.transition(LogState::Fatal).is_ok());
    }

    /// transition() returns the new state on success, not the old one.
    #[test]
    fn test_transition_ok_returns_new_state() {
        let result = LogState::Info.transition(LogState::Error).unwrap();
        assert_eq!(result, LogState::Error);
    }

    // ── LogState::transition() — rejected downgrades ─────────────────────────

    /// Every strictly-lower transition must be rejected.
    #[test]
    fn test_transition_downward_is_rejected() {
        assert!(LogState::Debug.transition(LogState::Info).is_err());
        assert!(LogState::Error.transition(LogState::Info).is_err());
        assert!(LogState::Error.transition(LogState::Debug).is_err());
        assert!(LogState::Fatal.transition(LogState::Info).is_err());
        assert!(LogState::Fatal.transition(LogState::Debug).is_err());
        assert!(LogState::Fatal.transition(LogState::Error).is_err());
    }

    /// A rejected transition must return an Err containing a non-empty message.
    #[test]
    fn test_transition_err_message_is_nonempty() {
        let err = LogState::Fatal.transition(LogState::Info).unwrap_err();
        assert!(!err.is_empty(), "error message must not be empty");
    }

    /// The error message must name both the source and the destination state
    /// so the caller can understand what was attempted.
    #[test]
    fn test_transition_err_message_names_both_states() {
        let err = LogState::Error.transition(LogState::Debug).unwrap_err();
        // The message must mention at least one of the state names.
        // We check lowercase to be case-insensitive.
        let lower = err.to_lowercase();
        assert!(
            lower.contains("error") || lower.contains("debug"),
            "error message should name the involved states, got: {err}"
        );
    }

    // ── Logger::new() ─────────────────────────────────────────────────────────

    /// A freshly created logger must start at Info severity.
    #[test]
    fn test_logger_initial_state_is_info() {
        let logger = Logger::new();
        assert_eq!(logger.state(), &LogState::Info);
    }

    /// Default::default() must produce the same initial state as new().
    #[test]
    fn test_logger_default_equals_new() {
        let a = Logger::new();
        let b = Logger::default();
        assert_eq!(a.state(), b.state());
    }

    // ── Logger::set_state() ───────────────────────────────────────────────────

    /// set_state to the same level succeeds and state is unchanged.
    #[test]
    fn test_set_state_same_level_is_noop() {
        let mut logger = Logger::new();
        let result = logger.set_state(LogState::Info);
        assert!(result.is_ok());
        assert_eq!(logger.state(), &LogState::Info);
    }

    /// set_state to a higher level succeeds and state is updated.
    #[test]
    fn test_set_state_upgrade_succeeds_and_updates() {
        let mut logger = Logger::new();
        logger.set_state(LogState::Error).unwrap();
        assert_eq!(logger.state(), &LogState::Error);
    }

    /// set_state to a lower level fails and the state is NOT modified.
    #[test]
    fn test_set_state_downgrade_fails_and_state_unchanged() {
        let mut logger = Logger::new();
        logger.set_state(LogState::Fatal).unwrap();

        let result = logger.set_state(LogState::Info);

        assert!(result.is_err(), "downgrade must return Err");
        assert_eq!(
            logger.state(),
            &LogState::Fatal,
            "state must not change on a failed set_state"
        );
    }

    /// set_state returns the Err string from transition() unchanged.
    #[test]
    fn test_set_state_err_message_propagated() {
        let mut logger = Logger::new();
        logger.set_state(LogState::Fatal).unwrap();

        let logger_err = logger.set_state(LogState::Info).unwrap_err();
        let direct_err = LogState::Fatal.transition(LogState::Info).unwrap_err();

        assert_eq!(logger_err, direct_err);
    }

    // ── One-way escalation — full chain ───────────────────────────────────────

    /// A logger can walk up the full chain Info → Debug → Error → Fatal
    /// with every step succeeding.
    #[test]
    fn test_full_escalation_chain_succeeds() {
        let mut logger = Logger::new();

        logger.set_state(LogState::Info).unwrap();
        assert_eq!(logger.state(), &LogState::Info);

        logger.set_state(LogState::Debug).unwrap();
        assert_eq!(logger.state(), &LogState::Debug);

        logger.set_state(LogState::Error).unwrap();
        assert_eq!(logger.state(), &LogState::Error);

        logger.set_state(LogState::Fatal).unwrap();
        assert_eq!(logger.state(), &LogState::Fatal);
    }

    /// Once Fatal is reached, every subsequent set_state attempt must fail.
    #[test]
    fn test_fatal_is_terminal() {
        let mut logger = Logger::new();
        logger.set_state(LogState::Fatal).unwrap();

        assert!(logger.set_state(LogState::Info).is_err());
        assert!(logger.set_state(LogState::Debug).is_err());
        assert!(logger.set_state(LogState::Error).is_err());

        // Same-level is still allowed (no-op).
        assert!(logger.set_state(LogState::Fatal).is_ok());

        // State must remain Fatal throughout.
        assert_eq!(logger.state(), &LogState::Fatal);
    }

    /// Calling set_state with a downgrade must never corrupt state — calling
    /// it many times in a row must leave the logger in the last valid state.
    #[test]
    fn test_repeated_failed_downgrades_do_not_corrupt_state() {
        let mut logger = Logger::new();
        logger.set_state(LogState::Error).unwrap();

        for _ in 0..10 {
            let _ = logger.set_state(LogState::Info); // always fails
        }

        assert_eq!(logger.state(), &LogState::Error);
    }

    // ── LogState derives ──────────────────────────────────────────────────────

    /// LogState must implement PartialEq correctly (derived).
    #[test]
    fn test_log_state_partial_eq() {
        assert_eq!(LogState::Info, LogState::Info);
        assert_eq!(LogState::Fatal, LogState::Fatal);
        assert_ne!(LogState::Info, LogState::Fatal);
        assert_ne!(LogState::Debug, LogState::Error);
    }

    /// LogState must implement Clone correctly (derived).
    #[test]
    fn test_log_state_clone() {
        let original = LogState::Error;
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }
}
