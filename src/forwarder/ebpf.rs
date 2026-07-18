// src/forwarder/ebpf.rs
//
// Loads the in-kernel MITM relay eBPF program (compiled from harper-ebpf/
// via build.rs) and attaches it as a tc ingress filter on the MITM interface.
//
// Replaces the userspace PacketForwarder copy + fragment + retry path. The
// victim->gateway / gateway->victim next-hop MAC mapping is held in a BPF hash
// map (key = source MAC, value = next-hop MAC) populated from userspace as
// victims are enabled/disabled.

use crate::host::table::HostId;
use aya::programs::tc::{SchedClassifier, TcAttachType};
use aya::maps::{Array, HashMap};
use aya::EbpfLoader;
use pnet::datalink::MacAddr;
use std::collections::HashMap as StdHashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Bytes of a MAC address.
const ETH_ALEN: usize = 6;

/// Handle to the running in-kernel relay. The `Ebpf` instance is kept alive for
/// the process lifetime so the attached tc program is not detached (matching the
/// tc/nft teardown on Ctrl-C). `KernelRelay` is `Send` (shared via `Arc<RelayHandle>`
/// across tokio worker threads) because `Ebpf` and the map fd are `Send`.
pub struct KernelRelay {
    _bpf: aya::Ebpf,
    map: HashMap<aya::maps::MapData, [u8; ETH_ALEN], [u8; ETH_ALEN]>,
    rules: Arc<Mutex<StdHashMap<HostId, (MacAddr, MacAddr)>>>,
}

impl KernelRelay {
    /// Load + attach the relay program on `interface`. `our_mac` is written into
    /// the `harper_own` map so the program only rewrites frames addressed to us.
    pub fn attach(interface: &str, our_mac: MacAddr) -> Result<Self, Box<dyn std::error::Error>> {
        let obj_path = concat!(env!("OUT_DIR"), "/harper-ebpf.o");
        let bytes = std::fs::read(obj_path).map_err(|e| {
            format!("eBPF object not found at {obj_path} ({e}). Was it compiled? Need clang in PATH.")
        })?;

        // Independent ELF inspection so we can see exactly what aya's parser sees.
        Self::dump_elf(&bytes, obj_path);

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

        // The clsact qdisc must exist before attaching a tc program.
        aya::programs::tc::qdisc_add_clsact(interface).map_err(|e| {
            // AlreadyAttached / Exclusivity flag on are benign — a clsact
            // qdisc is already present on the interface. Any other error
            // is fatal.
            let s = format!("{e:?}");
            if !s.contains("AlreadyAttached") && !s.contains("Exclusivity flag on") {
                eprintln!("[!] kernel relay: qdisc_add_clsact failed: {e}");
            }
        });


        // Attach the tc ingress program.
// Load the tc program first — this triggers aya's map relocation pass,
// so it must happen before take_map on either map.
{
    let prog: &mut SchedClassifier = bpf
        .program_mut("harper_relay")
        .ok_or("harper_relay program missing from eBPF object")?
        .try_into()
        .map_err(|e| format!("not a tc program: {e}"))?;
    prog.load().map_err(|e| format!("failed to load tc program: {e}"))?;
}
// `prog`'s borrow of `bpf` ends here.

// Now safe to take_map — relocation already happened at load() time.
{
    let mut own_map: Array<aya::maps::MapData, [u8; ETH_ALEN]> =
        Array::try_from(bpf.take_map("harper_own").ok_or("harper_own map missing")?)?;
    own_map
        .set(0, our_mac.octets(), 0)
        .map_err(|e| format!("failed to set own MAC: {e}"))?;
}

let map: HashMap<aya::maps::MapData, [u8; ETH_ALEN], [u8; ETH_ALEN]> =
    HashMap::try_from(bpf.take_map("harper_map").ok_or("harper_map map missing")?)?;

// Re-borrow `bpf` fresh for attach — separate borrow, no conflict.
let prog: &mut SchedClassifier = bpf
    .program_mut("harper_relay")
    .ok_or("harper_relay program missing from eBPF object")?
    .try_into()
    .map_err(|e| format!("not a tc program: {e}"))?;
let _link = prog
    .attach(interface, TcAttachType::Ingress)
    .map_err(|e| format!("failed to attach tc ingress on {interface}: {e}"))?;

        println!("[+] kernel relay: attached eBPF tc ingress on {interface}");

        Ok(Self {
            _bpf: bpf,
            map,
            rules: Arc::new(Mutex::new(StdHashMap::new())),
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

    /// Print an independent view of the eBPF ELF so we can see exactly what aya's
    /// parser is looking at when it fails. aya's parser consumes the map section
    /// bytes + the `harper_map`/`harper_own`/`harper_relay` symbols.
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
                || name.starts_with("classifier");
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
                if name == "harper_map" || name == "harper_own" || name == "harper_relay" {
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
                "[*] kernel relay: WARNING — no harper_map/harper_own/harper_relay symbols found"
            );
        }
    }
}
