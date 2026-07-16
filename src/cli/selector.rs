// src/cli/selector.rs
use crate::cli::color::*;
use crate::paint;

use crate::utils::check_interfaces::scan;
use crate::utils::logger::*;

use std::io::{self, Write};

pub struct InterfaceSelector;

impl InterfaceSelector {
    pub fn select(only_wlan_eth: bool) -> Option<String> {
        let mut logger = Logger::new();

        let interfaces = scan(only_wlan_eth);

        if interfaces.is_empty() {
            logger.fatal_fmt(format_args!(
                "No network interfaces found! Make sure you have an active connection"
            ));
            return None;
        }

        println!("\n{}", "=".repeat(52));
        println!("{:^52}", "Available Network Interfaces");
        println!("{}", "=".repeat(52));
        println!();
        println!(
            "{:<4} {:<12} {:<10} {:<6} {}",
            "ID", "NAME", "TYPE", "UP", "MAC"
        );
        println!("{}", "-".repeat(52));

        for (idx, iface) in interfaces.iter().enumerate() {
            println!(
                "{:<4} {:<12} {:<10} {:<6} {}",
                format!("[{}]", idx + 1),
                iface.name,
                format!("{:?}", iface.kind),
                if iface.is_up { "yes" } else { "no" },
                iface.mac.as_deref().unwrap_or("unknown"),
            );
        }

        println!("{}", "-".repeat(52));

        print!(
            "{}",
            paint!(
                &palette::MESSAGE,
                "Select interface [1-{}] (or 'q' to quit): ",
                interfaces.len()
            )
        );

        io::stdout().flush().unwrap();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            return None;
        }

        Self::parse_input(input.trim(), interfaces.len()).map(|idx| interfaces[idx].name.clone())
    }

    /// Pure function: maps a trimmed user input string and the number of
    /// available interfaces to a zero-based index into the interface list.
    ///
    /// Returns:
    ///   `Some(index)` — valid 1-based numeric selection, converted to 0-based
    ///   `None`        — quit command ("q" / "quit") or invalid input
    pub(crate) fn parse_input(input: &str, count: usize) -> Option<usize> {
        if input.eq_ignore_ascii_case("q") || input.eq_ignore_ascii_case("quit") {
            return None;
        }

        match input.parse::<usize>() {
            Ok(num) if num >= 1 && num <= count => Some(num - 1),
            _ => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Quit commands ─────────────────────────────────────────────────────────
    // All quit-variant cases together; they all share the same contract.
    #[test]
    fn test_quit_variants_return_none() {
        for variant in ["q", "Q", "quit", "Quit", "QUIT", "qUiT"] {
            assert!(
                InterfaceSelector::parse_input(variant, 5).is_none(),
                "'{variant}' should be treated as quit"
            );
        }
    }

    // ── Valid selections ──────────────────────────────────────────────────────
    // All valid numeric selections in one table.
    #[test]
    fn test_valid_selections() {
        // (input, count, expected_index)
        let cases = [
            ("1", 3, 0),  // first item
            ("3", 3, 2),  // last item
            ("2", 5, 1),  // middle item
            ("1", 1, 0),  // single interface
        ];
        for (input, count, expected) in cases {
            assert_eq!(
                InterfaceSelector::parse_input(input, count),
                Some(expected),
                "input '{input}' of {count} should give index {expected}"
            );
        }
    }

    // Returned index is always exactly (input_number - 1) — verify across a range
    #[test]
    fn test_returned_index_is_one_based_converted() {
        for n in 1usize..=10 {
            assert_eq!(
                InterfaceSelector::parse_input(&n.to_string(), 10),
                Some(n - 1)
            );
        }
    }

    // ── Invalid / out-of-range inputs ─────────────────────────────────────────
    // Every case that should return None (excluding quit variants above).
    #[test]
    fn test_invalid_inputs_return_none() {
        // (input, count, reason)
        let cases: &[(&str, usize, &str)] = &[
            ("0",    5, "zero is not 1-based"),
            ("4",    3, "one above count"),
            ("9999", 3, "way above count"),
            ("1",    0, "no interfaces available"),
            ("0",    0, "zero with no interfaces"),
            ("eth0", 5, "non-numeric word"),
            ("hello",5, "arbitrary word"),
            ("",     5, "empty string"),
            ("   ",  5, "whitespace only"),
            ("1.0",  5, "float"),
            ("-1",   5, "negative number"),
            (" 1 ",  5, "untrimmed number"),
            ("1x",   5, "trailing char"),
            ("2 ",   5, "trailing space"),
        ];
        for &(input, count, reason) in cases {
            assert!(
                InterfaceSelector::parse_input(input, count).is_none(),
                "'{input}' ({reason}) should return None"
            );
        }
    }
}