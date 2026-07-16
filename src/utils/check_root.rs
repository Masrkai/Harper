use crate::utils::logger::*;
use nix::unistd::geteuid;

/// Pure logic — testable without root or process::exit.
/// Returns Ok(()) if root, Err with the message to display if not.
pub(crate) fn check_root_logic(is_root: bool) -> Result<&'static str, &'static str> {
    if is_root {
        Ok("Root privileges have been granted successfully")
    } else {
        Err("This tool requires root privileges for raw socket access, Try running with sudo!")
    }
}

pub fn check_root() {
    let mut logger = Logger::new();

    match check_root_logic(geteuid().is_root()) {
        Ok(msg) => logger.info_fmt(format_args!("{}", msg)),
        Err(msg) => {
            logger.info_fmt(format_args!("{}", msg));
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── check_root_logic() ────────────────────────────────────────────────────

    /// When is_root is true, the result must be Ok.
    #[test]
    fn test_root_returns_ok() {
        assert!(check_root_logic(true).is_ok());
    }

    /// When is_root is false, the result must be Err.
    #[test]
    fn test_non_root_returns_err() {
        assert!(check_root_logic(false).is_err());
    }

    /// The Ok message must be non-empty.
    #[test]
    fn test_root_ok_message_is_nonempty() {
        let msg = check_root_logic(true).unwrap();
        assert!(!msg.is_empty());
    }

    /// The Err message must be non-empty.
    #[test]
    fn test_non_root_err_message_is_nonempty() {
        let msg = check_root_logic(false).unwrap_err();
        assert!(!msg.is_empty());
    }

    /// The Ok and Err messages must be distinct — they communicate opposite
    /// outcomes, so accidentally returning the same string would be a bug.
    #[test]
    fn test_ok_and_err_messages_are_distinct() {
        let ok_msg = check_root_logic(true).unwrap();
        let err_msg = check_root_logic(false).unwrap_err();
        assert_ne!(ok_msg, err_msg);
    }

    /// check_root_logic is pure — calling it multiple times with the same
    /// argument always returns the same result.
    #[test]
    fn test_idempotent_true() {
        assert_eq!(check_root_logic(true), check_root_logic(true));
    }

    #[test]
    fn test_idempotent_false() {
        assert_eq!(check_root_logic(false), check_root_logic(false));
    }

    // ── Live integration (requires actual root) ───────────────────────────────

    /// Verifies that geteuid().is_root() returns true when the test runner
    /// is actually root.  Run with: sudo cargo test -- --ignored
    #[test]
    #[ignore]
    fn test_check_root_logic_matches_real_uid() {
        let real_is_root = nix::unistd::geteuid().is_root();
        if real_is_root {
            assert!(check_root_logic(true).is_ok());
        } else {
            assert!(check_root_logic(false).is_err());
        }
    }
}
