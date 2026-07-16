/// Reads a sysctl value, returning `None` if it cannot be read.
/// Callers must handle the `None` case explicitly rather than assuming a
/// default — a failed read must not be silently treated as "0".
pub fn read_proc(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .map_err(|e| eprintln!("[!] Failed to read sysctl {path}: {e}"))
        .ok()
}
