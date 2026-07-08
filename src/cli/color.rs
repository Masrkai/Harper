const RESET: &str = "\x1b[0m";

pub const fn parse_hex(hex: &[u8]) -> (u8, u8, u8) {
    assert!(
        hex.len() == 7 || hex.len() == 9,
        "color must be '#RRGGBB' or '#RRGGBBAA' (7 or 9 chars)"
    );
    assert!(hex[0] == b'#', "color must start with '#'");

    const fn val(b: u8) -> u8 {
        match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => panic!("invalid hex digit"),
        }
    }

    let r = (val(hex[1]) << 4) | val(hex[2]);
    let g = (val(hex[3]) << 4) | val(hex[4]);
    let b = (val(hex[5]) << 4) | val(hex[6]);
    // alpha (hex[7..=8]) is silently ignored — terminals don't support it
    (r, g, b)
}

pub struct Color(pub u8, pub u8, pub u8);

impl Color {
    pub const fn from_hex(hex: &[u8]) -> Self {
        let (r, g, b) = parse_hex(hex);
        Self(r, g, b)
    }

    pub fn paint(&self, text: &str) -> String {
        let Self(r, g, b) = self;
        format!("\x1b[38;2;{r};{g};{b}m{text}{RESET}")
    }

    pub fn paint_fmt(&self, args: std::fmt::Arguments) -> String {
        let Self(r, g, b) = self;
        format!("\x1b[38;2;{r};{g};{b}m{args}{RESET}")
    }
}

#[macro_export]
macro_rules! paint {
    ($color:expr, $($arg:tt)*) => {
        $color.paint_fmt(format_args!($($arg)*))
    };
}

// ── Compile-time assertions ───────────────────────────────────────────────────

const _: () = {
    let (r, g, b) = parse_hex(b"#FFFFFF");
    assert!(r == 255 && g == 255 && b == 255);
};
const _: () = {
    let (r, g, b) = parse_hex(b"#000000");
    assert!(r == 0 && g == 0 && b == 0);
};
const _: () = {
    let (r, g, b) = parse_hex(b"#C792EA");
    assert!(r == 0xC7 && g == 0x92 && b == 0xEA);
};
const _: () = {
    let (r, g, b) = parse_hex(b"#50c878");
    assert!(r == 0x50 && g == 0xC8 && b == 0x78);
};
const _: () = {
    let (r, g, b) = parse_hex(b"#FF5050FF");
    assert!(r == 0xFF && g == 0x50 && b == 0x50);
};
const _: () = {
    let (r, g, b) = parse_hex(b"#010203");
    assert!(r == 1 && g == 2 && b == 3);
};

// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_hex: correct decoding ───────────────────────────────────────────
    // All "known good" cases in one table: (input, expected (r, g, b))
    #[test]
    fn test_parse_hex_valid_inputs() {
        let cases: &[(&[u8], (u8, u8, u8))] = &[
            (b"#FFFFFF", (255, 255, 255)),   // pure white
            (b"#000000", (0, 0, 0)),         // pure black
            (b"#FF0000", (255, 0, 0)),       // pure red
            (b"#00FF00", (0, 255, 0)),       // pure green
            (b"#0000FF", (0, 0, 255)),       // pure blue
            (b"#C792EA", (0xC7, 0x92, 0xEA)), // purple used in codebase
            (b"#50c878", (0x50, 0xC8, 0x78)), // lowercase digits
            (b"#Ff8800", (0xFF, 0x88, 0x00)), // mixed case
            (b"#010203", (1, 2, 3)),           // boundary nibbles
            (b"#09AF00", (0x09, 0xAF, 0x00)), // all hex digit classes
            (b"#1a2b3c", (0x1A, 0x2B, 0x3C)),
        ];
        for &(input, expected) in cases {
            assert_eq!(
                parse_hex(input), expected,
                "parse_hex({}) failed", std::str::from_utf8(input).unwrap_or("?")
            );
        }
    }

    // 9-byte form: alpha is silently discarded regardless of its value
    #[test]
    fn test_parse_hex_9_byte_alpha_ignored() {
        assert_eq!(parse_hex(b"#FF5050FF"), parse_hex(b"#FF5050"));
        assert_eq!(parse_hex(b"#FF505000"), parse_hex(b"#FF5050"));
    }

    // Lowercase == uppercase for the same hex digits
    #[test]
    fn test_parse_hex_case_insensitive() {
        assert_eq!(parse_hex(b"#50c878"), parse_hex(b"#50C878"));
    }

    // ── parse_hex: panic paths ────────────────────────────────────────────────
    // All invalid inputs in one table: (input, description)
    #[test]
    fn test_parse_hex_invalid_inputs_panic() {
        // Each closure must panic; we verify this with catch_unwind.
        let bad_inputs: &[&[u8]] = &[
            b"#FF00",      // too short (5 bytes)
            b"#FF0000AABB", // too long (11 bytes)
            b"#FF0000A",   // 8 bytes — neither 7 nor 9
            b"FF0000",     // missing '#'
            b"#FF",        // '#' present but wrong length
            b"#GG0000",    // invalid hex char 'G'
            b"#FF 000",    // space in digits
        ];
        for &input in bad_inputs {
            let result = std::panic::catch_unwind(|| parse_hex(input));
            assert!(
                result.is_err(),
                "'{}' should panic but did not",
                std::str::from_utf8(input).unwrap_or("<binary>")
            );
        }
    }

    // ── Color::paint ──────────────────────────────────────────────────────────
    #[test]
    fn test_paint_ansi_escape_format() {
        // Verifies the exact ANSI true-color escape sequence structure.
        let cases: &[(u8, u8, u8, &str, &str)] = &[
            (255, 128,   0, "hello", "\x1b[38;2;255;128;0mhello\x1b[0m"),
            (  0,   0,   0, "x",     "\x1b[38;2;0;0;0mx\x1b[0m"),
            (255, 255, 255, "y",     "\x1b[38;2;255;255;255my\x1b[0m"),
            (  0,   0,   0, "",      "\x1b[38;2;0;0;0m\x1b[0m"),   // empty text
        ];
        for &(r, g, b, text, expected) in cases {
            assert_eq!(Color(r, g, b).paint(text), expected);
        }
    }

    #[test]
    fn test_paint_always_wraps_with_reset() {
        // Structural invariants that hold for any color/text combination.
        let color = Color(1, 2, 3);
        let painted = color.paint("harper");
        assert!(painted.starts_with("\x1b[38;2;"));
        assert!(painted.ends_with("\x1b[0m"));
        assert!(painted.contains("harper"));
    }

    // ── Color::from_hex ───────────────────────────────────────────────────────
    #[test]
    fn test_from_hex_stores_parsed_bytes() {
        let cases: &[(&[u8], (u8, u8, u8))] = &[
            (b"#C792EA", (0xC7, 0x92, 0xEA)),
            (b"#000000", (0, 0, 0)),
        ];
        for &(input, (er, eg, eb)) in cases {
            let c = Color::from_hex(input);
            assert_eq!((c.0, c.1, c.2), (er, eg, eb));
        }
    }

    // ── paint! macro ──────────────────────────────────────────────────────────
    #[test]
    fn test_paint_macro() {
        let color = Color(80, 200, 120);

        // Output matches direct paint() with equivalent format string
        assert_eq!(
            crate::paint!(&color, "value: {}", 42),
            color.paint("value: 42")
        );

        // Structural invariants still hold through the macro
        let result = crate::paint!(&Color(255, 0, 0), "{} + {} = {}", 1, 2, 3);
        assert!(result.contains("1 + 2 = 3"));
        assert!(result.starts_with("\x1b[38;2;"));
        assert!(result.ends_with("\x1b[0m"));
    }
}