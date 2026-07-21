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

fn compile_ebpf(source: &str, out_name: &str, inc: Option<&PathBuf>) {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let obj = out_dir.join(out_name);

    let mut cmd = Command::new("clang");
    cmd.args(["-O2", "-g", "-target", "bpf", "-c", source, "-o"]);
    cmd.arg(&obj);
    if let Some(inc) = inc {
        cmd.arg("-I");
        cmd.arg(inc);
    }

    match cmd.status() {
        Ok(s) if s.success() => {}
        Ok(s) => {
            panic!(
                "eBPF build failed for {source} (clang exit {s}); \
                 fix the C source or ensure libbpf headers are available via LIBBPF_INCLUDE."
            );
        }
        Err(e) => {
            eprintln!(
                "cargo:warning=clang not found ({e}); eBPF backends will be \
                 unavailable at runtime. Add clang + libbpf to the build environment."
            );
        }
    }
}

fn main() {
    println!("cargo:rerun-if-changed=harper-ebpf/harper_tc.bpf.c");
    println!("cargo:rerun-if-changed=harper-ebpf/harper_legacy.bpf.c");
    println!("cargo:rerun-if-changed=harper-ebpf/harper_xdp.bpf.c");
    println!("cargo:rerun-if-env-changed=LIBBPF_INCLUDE");

    let inc = find_libbpf_include();
    let inc_ref = inc.as_ref();

    compile_ebpf("harper-ebpf/harper_tc.bpf.c", "harper_tc-ebpf.o", inc_ref);
    compile_ebpf(
        "harper-ebpf/harper_legacy.bpf.c",
        "harper_legacy-ebpf.o",
        inc_ref,
    );
    compile_ebpf(
        "harper-ebpf/harper_xdp.bpf.c",
        "harper_xdp-ebpf.o",
        inc_ref,
    );
}
