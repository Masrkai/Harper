// build.rs — compiles the harper-ebpf C object from clang at build time.
//
// Produces target/<profile>/build/harper-<hash>/out/harper-ebpf.o (exposed via
// the `OUT_DIR` env var) so the loader (src/forwarder/ebpf.rs) can read it.
//
// The eBPF C source needs libbpf's `bpf/` + `linux/` headers. On NixOS these
// live under a libbpf store path; point build.rs at them via the LIBBPF_INCLUDE
// env var, or it will probe common Nix store locations. If clang or the headers
// are unavailable the build still succeeds but --kernel mode is unavailable at
// runtime (the loader reports a clear error).
use std::env;
use std::path::PathBuf;
use std::process::Command;

fn find_libbpf_include() -> Option<PathBuf> {
    if let Ok(p) = env::var("LIBBPF_INCLUDE") {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return Some(pb);
        }
    }
    // Probe common Nix store layout: <libbpf>/include/{bpf/bpf_helpers.h}.
    let store = PathBuf::from("/nix/store");
    if store.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&store) {
            for e in entries.flatten() {
                let inc = e.path().join("include");
                if inc.join("bpf/bpf_helpers.h").is_file() {
                    return Some(inc);
                }
            }
        }
    }
    None
}

fn main() {
    println!("cargo:rerun-if-changed=harper-ebpf/harper.bpf.c");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let obj = out_dir.join("harper-ebpf.o");

    let mut cmd = Command::new("clang");
    // `-g` emits BTF debug info so aya 0.14 can parse the BTF-style `.maps`
    // definitions; without it the verifier rejects map fds.
    cmd.args(["-O2", "-g", "-target", "bpf", "-c", "harper-ebpf/harper.bpf.c", "-o"]);
    cmd.arg(&obj);
    if let Some(inc) = find_libbpf_include() {
        cmd.arg("-I");
        cmd.arg(inc);
    }

    match cmd.status() {
        Ok(s) if s.success() => {
            println!("cargo:rerun-if-env-changed=LIBBPF_INCLUDE");
        }
        Ok(s) => {
            eprintln!(
                "cargo:warning=harper-ebpf build failed (clang exit {s}); \
                 --kernel mode will be unavailable at runtime. Set LIBBPF_INCLUDE if headers are elsewhere."
            );
        }
        Err(e) => {
            eprintln!(
                "cargo:warning=clang not found ({e}); --kernel mode will be \
                 unavailable at runtime. Add clang + libbpf to the build environment."
            );
        }
    }
}
