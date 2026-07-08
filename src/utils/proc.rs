pub fn read_proc(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|_| "0\n".to_string())
}
