// build.rs — compiles the harper-ebpf C object from clang at build time.
//
// Produces target/<profile>/build/harper-<hash>/out/harper-ebpf.o (exposed via
// the `OUT_DIR` env var) so the loader (src/forwarder/ebpf.rs) can read it.
//
// The eBPF C source needs libbpf's `bpf/` + `linux/` headers. On NixOS these
// live under a libbpf store path; point build.rs at them via the LIBBPF_INCLUDE
// env var, or it will probe common Nix store locations.
//
// clang must support cross-target compilation. On NixOS the wrapped clang
// injects host-specific flags invalid for the `bpf` target, so `find_unwrapped_clang`
// probes the store for an unwrapped clang. Set CLANG to override.
//
// If clang is not found the build still succeeds with a warning (--kernel mode
// will be unavailable at runtime). If clang runs but exits non-zero the build
// fails — that indicates a real compilation error.
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

/// Find Linux kernel uapi headers for BPF cross-compilation.
///
/// The libbpf `linux/bpf.h` includes `<linux/types.h>`, which belongs to the
/// kernel headers, not libbpf.  When targeting `bpf` we need to add them via
/// `-idirafter` so standard kernel types resolve correctly.
fn find_kernel_include() -> Option<PathBuf> {
    if let Ok(p) = env::var("KERNEL_INCLUDE") {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return Some(pb);
        }
    }
    let store = PathBuf::from("/nix/store");
    if store.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&store) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if name.contains("linux-headers") {
                    let inc = e.path().join("include");
                    if inc.join("linux/types.h").is_file() {
                        return Some(inc);
                    }
                }
            }
        }
    }
    None
}

/// Find an unwrapped clang binary suitable for cross-target compilation (e.g. `-target bpf`).
///
/// The NixOS clang wrapper injects host-specific flags that are invalid for non-native
/// targets, so we prefer an unwrapped clang when available.
fn find_unwrapped_clang() -> PathBuf {
    // Respect CLANG env var override.
    if let Ok(p) = env::var("CLANG") {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return pb;
        }
    }
    // Probe Nix store for unwrapped clang (store path contains "-clang-" but not "-wrapper-").
    let store = PathBuf::from("/nix/store");
    if store.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&store) {
            let mut candidates: Vec<PathBuf> = entries
                .flatten()
                .filter_map(|e| {
                    let name = e.file_name().to_string_lossy().to_string();
                    if name.contains("-clang-") && !name.contains("-wrapper-") {
                        let bin = e.path().join("bin").join("clang");
                        bin.is_file().then_some(bin)
                    } else {
                        None
                    }
                })
                .collect();
            candidates.sort();
            if let Some(best) = candidates.last() {
                return best.clone();
            }
        }
    }
    // Fallback: let PATH resolve clang (works on non-NixOS systems).
    PathBuf::from("clang")
}

fn compile_ebpf(source: &str, out_name: &str, inc: Option<&PathBuf>, kernel_inc: Option<&PathBuf>) {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let obj = out_dir.join(out_name);

    let clang = find_unwrapped_clang();
    let mut cmd = Command::new(&clang);
    cmd.args(["-O2", "-g", "-target", "bpf", "-c", source, "-o"]);
    cmd.arg(&obj);
    if let Some(inc) = inc {
        cmd.arg("-I");
        cmd.arg(inc);
    }
    if let Some(kinc) = kernel_inc {
        cmd.arg("-idirafter");
        cmd.arg(kinc);
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
    println!("cargo:rerun-if-env-changed=KERNEL_INCLUDE");

    let inc = find_libbpf_include();
    let inc_ref = inc.as_ref();
    let kernel_inc = find_kernel_include();
    let kernel_inc_ref = kernel_inc.as_ref();

    compile_ebpf("harper-ebpf/harper_tc.bpf.c", "harper_tc-ebpf.o", inc_ref, kernel_inc_ref);
    compile_ebpf(
        "harper-ebpf/harper_legacy.bpf.c",
        "harper_legacy-ebpf.o",
        inc_ref,
        kernel_inc_ref,
    );
    compile_ebpf(
        "harper-ebpf/harper_xdp.bpf.c",
        "harper_xdp-ebpf.o",
        inc_ref,
        kernel_inc_ref,
    );
}
