// src/forwarder/ebpf.rs
//
// Loads the in-kernel MITM relay eBPF programs (compiled from harper-ebpf/
// via build.rs) and attaches them on the MITM interface.
//
// Three backends are available, selected at runtime:
//   - Xdp:        XDP program + DEVMAP, no SKB allocation
//   - TcRedirect: tc ingress + DEVMAP, bypasses kernel stack
//   - TcLegacy:   tc ingress + MAC rewrite, kernel stack traversal
//
// The default is TcRedirect. XDP is tried first if --xdp is requested
// and the interface supports it.

use crate::host::table::HostId;
use aya::EbpfLoader;
use aya::maps::{Array, HashMap};
use aya::maps::xdp::DevMap;
use aya::programs::tc::{SchedClassifier, TcAttachType};
use aya::programs::XdpMode;
use pnet::datalink::MacAddr;
use std::collections::HashMap as StdHashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Bytes of a MAC address.
const ETH_ALEN: usize = 6;

/// The in-kernel relay backend in use.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RelayBackend {
    /// XDP program + DEVMAP (fastest).
    Xdp,
    /// tc ingress + DEVMAP (bypasses kernel stack).
    TcRedirect,
    /// tc ingress + MAC rewrite + TC_ACT_OK (kernel stack traversal).
    TcLegacy,
}

/// Handle to the running in-kernel relay. The `Ebpf` instance is kept alive for
/// the process lifetime so the attached program is not detached (matching the
/// tc/nft teardown on Ctrl-C). `KernelRelay` is `Send` (shared via `Arc<RelayHandle>`
/// across tokio worker threads) because `Ebpf` and the map fd are `Send`.
pub struct KernelRelay {
    _bpf: aya::Ebpf,
    map: HashMap<aya::maps::MapData, [u8; ETH_ALEN], [u8; ETH_ALEN]>,
    rules: Arc<Mutex<StdHashMap<HostId, (MacAddr, MacAddr)>>>,
    pub backend: RelayBackend,
}

impl KernelRelay {
    /// Attach the best available relay backend for the interface.
    ///
    /// Selection order:
    /// - `RelayBackend::Xdp`       → try XDP, error if unsupported
    /// - `RelayBackend::TcRedirect` → try tc redirect, fall back to legacy
    /// - `RelayBackend::TcLegacy`   → use legacy tc (TC_ACT_OK)
    pub fn attach_best_available(
        interface: &str,
        our_mac: MacAddr,
        preference: RelayBackend,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        match preference {
            RelayBackend::Xdp => {
                if !probe_xdp_support(interface) {
                    return Err(
                        "XDP not supported on this interface. Try --kernel or --legacy.".into(),
                    );
                }
                Self::attach_inner(interface, our_mac, "harper_xdp-ebpf.o", RelayBackend::Xdp)
            }
            RelayBackend::TcRedirect => {
                match Self::attach_inner(
                    interface,
                    our_mac,
                    "harper_tc-ebpf.o",
                    RelayBackend::TcRedirect,
                ) {
                    Ok(r) => Ok(r),
                    Err(e) => {
                        eprintln!(
                            "[!] tc redirect attach failed: {e}. Falling back to legacy tc."
                        );
                        Self::attach_inner(
                            interface,
                            our_mac,
                            "harper_legacy-ebpf.o",
                            RelayBackend::TcLegacy,
                        )
                    }
                }
            }
            RelayBackend::TcLegacy => {
                Self::attach_inner(
                    interface,
                    our_mac,
                    "harper_legacy-ebpf.o",
                    RelayBackend::TcLegacy,
                )
            }
        }
    }

    /// Load and attach a specific eBPF program by object file name.
    fn attach_inner(
        interface: &str,
        our_mac: MacAddr,
        obj_name: &str,
        backend: RelayBackend,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let obj_path = format!("{}/{}", env!("OUT_DIR"), obj_name);
        let bytes = std::fs::read(&obj_path).map_err(|e| {
            format!(
                "eBPF object not found at {obj_path} ({e}). Was it compiled? Need clang in PATH."
            )
        })?;

        #[cfg(feature = "debug-ebpf")]
        Self::dump_elf(&bytes, &obj_path);

        let mut bpf = match EbpfLoader::new().load(&bytes) {
            Ok(bpf) => bpf,
            Err(e) => {
                eprintln!(
                    "[!] kernel relay: eBPF load failed. object={} ({} bytes)\n\
                     \x20   error:   {e}\n\
                     \x20   debug:   {e:?}",
                    obj_path,
                    bytes.len()
                );
                return Err(format!("failed to load eBPF object: {e:?}").into());
            }
        };

        // For tc backends, the clsact qdisc must exist before attaching.
        if backend != RelayBackend::Xdp {
            aya::programs::tc::qdisc_add_clsact(interface).map_err(|e| {
                let s = format!("{e:?}");
                if !s.contains("AlreadyAttached") && !s.contains("Exclusivity flag on") {
                    eprintln!("[!] kernel relay: qdisc_add_clsact failed: {e}");
                }
            });
        }

        // Load the program first — triggers aya's map relocation pass.
        match backend {
            RelayBackend::Xdp => {
                let prog: &mut aya::programs::Xdp = bpf
                    .program_mut("harper_relay")
                    .ok_or("harper_relay program missing from eBPF object")?
                    .try_into()
                    .map_err(|e| format!("not an XDP program: {e}"))?;
                prog.load()
                    .map_err(|e| format!("failed to load XDP program: {e}"))?;
            }
            _ => {
                let prog: &mut SchedClassifier = bpf
                    .program_mut("harper_relay")
                    .ok_or("harper_relay program missing from eBPF object")?
                    .try_into()
                    .map_err(|e| format!("not a tc program: {e}"))?;
                prog.load()
                    .map_err(|e| format!("failed to load tc program: {e}"))?;
            }
        }

        // Populate harper_own with our MAC (all backends).
        {
            let mut own_map: Array<aya::maps::MapData, [u8; ETH_ALEN]> =
                Array::try_from(bpf.take_map("harper_own").ok_or("harper_own map missing")?)?;
            own_map
                .set(0, our_mac.octets(), 0)
                .map_err(|e| format!("failed to set own MAC: {e}"))?;
        }

        // Populate egress_iface_map with the interface ifindex (XDP + tc redirect).
        if backend != RelayBackend::TcLegacy {
            let mut devmap: DevMap<_> = DevMap::try_from(
                bpf.take_map("egress_iface_map")
                    .ok_or("egress_iface_map missing")?,
            )?;
            let ifindex = nix::net::if_::if_nametoindex(interface)
                .map_err(|e| format!("failed to resolve ifindex for {interface}: {e}"))?;
            devmap
                .set(0, ifindex, None, 0)
                .map_err(|e| format!("failed to set devmap entry: {e}"))?;
        }

        let map: HashMap<aya::maps::MapData, [u8; ETH_ALEN], [u8; ETH_ALEN]> =
            HashMap::try_from(bpf.take_map("harper_map").ok_or("harper_map map missing")?)?;

        // Attach.
        match backend {
            RelayBackend::Xdp => {
                let prog: &mut aya::programs::Xdp = bpf
                    .program_mut("harper_relay")
                    .ok_or("harper_relay program missing")?
                    .try_into()
                    .map_err(|e| format!("not an XDP program: {e}"))?;
                let _link = prog
                    .attach(interface, XdpMode::Default)
                    .map_err(|e| format!("failed to attach XDP on {interface}: {e}"))?;
                println!("[+] kernel relay: attached XDP on {interface}");
            }
            _ => {
                let prog: &mut SchedClassifier = bpf
                    .program_mut("harper_relay")
                    .ok_or("harper_relay program missing")?
                    .try_into()
                    .map_err(|e| format!("not a tc program: {e}"))?;
                let _link = prog
                    .attach(interface, TcAttachType::Ingress)
                    .map_err(|e| format!("failed to attach tc ingress on {interface}: {e}"))?;
                println!("[+] kernel relay: attached tc ingress on {interface}");
            }
        }

        Ok(Self {
            _bpf: bpf,
            map,
            rules: Arc::new(Mutex::new(StdHashMap::new())),
            backend,
        })
    }

    /// Enable relay for a victim: map both source MACs (victim + gateway) to
    /// their respective next-hop MACs.
    pub async fn enable(&mut self, host_id: HostId, victim_mac: MacAddr, gateway_mac: MacAddr) {
        {
            let mut rules = self.rules.lock().await;
            rules.insert(host_id, (victim_mac, gateway_mac));
        }
        let vm = victim_mac.octets();
        let gm = gateway_mac.octets();
        let _ = self
            .map
            .insert(vm, gm, 0)
            .map_err(|e| eprintln!("[!] kernel relay: map insert (victim) failed: {e}"));
        let _ = self
            .map
            .insert(gm, vm, 0)
            .map_err(|e| eprintln!("[!] kernel relay: map insert (gateway) failed: {e}"));
    }

    /// Remove a victim's mappings.
    pub async fn disable(&mut self, host_id: HostId) {
        let maybe = {
            let mut rules = self.rules.lock().await;
            rules.remove(&host_id)
        };
        if let Some((victim_mac, gateway_mac)) = maybe {
            let vm = victim_mac.octets();
            let gm = gateway_mac.octets();
            let _ = self.map.remove(&vm);
            let _ = self.map.remove(&gm);
        }
    }

    /// Remove all mappings.
    pub async fn disable_all(&mut self) {
        let ids: Vec<HostId> = {
            let rules = self.rules.lock().await;
            rules.keys().copied().collect()
        };
        for id in ids {
            self.disable(id).await;
        }
    }

    #[cfg(feature = "debug-ebpf")]
    fn dump_elf(bytes: &[u8], path: &str) {
        use object::{Object, ObjectSection, ObjectSymbol};

        let file = match object::File::parse(bytes) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("[!] kernel relay: could not parse ELF for inspection: {e}");
                return;
            }
        };

        eprintln!(
            "[*] kernel relay: inspecting eBPF object {} ({} bytes)",
            path,
            bytes.len()
        );
        eprintln!(
            "[*] kernel relay: ELF endianness={:?} architecture={:?}",
            file.endianness(),
            file.architecture()
        );

        for sec in file.sections() {
            let name = match sec.name() {
                Ok(n) => n,
                Err(_) => continue,
            };
            let interesting = name == "maps"
                || name == ".maps"
                || name == "license"
                || name == ".text"
                || name.starts_with("tc")
                || name.starts_with("classifier")
                || name.starts_with("xdp");
            if interesting {
                eprintln!(
                    "[*]   section {:>12}  kind={:?}  size={}",
                    name,
                    sec.kind(),
                    sec.size()
                );
            }
        }

        let mut found = false;
        for sym in file.symbols() {
            if let Ok(name) = sym.name() {
                if name == "harper_map"
                    || name == "harper_own"
                    || name == "harper_relay"
                    || name == "egress_iface_map"
                {
                    found = true;
                    eprintln!(
                        "[*]   symbol {:<12} section={:?} address={:#x} size={}",
                        name,
                        sym.section(),
                        sym.address(),
                        sym.size()
                    );
                }
            }
        }
        if !found {
            eprintln!(
                "[*] kernel relay: WARNING — no known symbols found in eBPF object"
            );
        }
    }
}

/// Probe whether XDP is available on the given interface.
///
/// Checks `/sys/class/net/<iface>/xdp_features` (kernel 6.x+). If the file
/// exists with a non-zero value, XDP is supported. If the file doesn't exist
/// (pre-6.x kernel), this returns false and the caller should fall back to
/// tc redirect.
pub(crate) fn probe_xdp_support(iface: &str) -> bool {
    let path = format!("/sys/class/net/{iface}/xdp_features");
    let features = match std::fs::read_to_string(&path) {
        Ok(s) => s.trim().to_string(),
        Err(_) => return false,
    };
    if features.is_empty() || features == "0" {
        return false;
    }
    true
}
