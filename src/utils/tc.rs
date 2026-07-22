// src/utils/tc.rs
//
// Per-host bandwidth shaping via `tc` + `nft`.
//
// ─────────────────────────────────────────────────────────────────────────────
// INGRESS REDIRECT — CORRECT ARCHITECTURE
// ─────────────────────────────────────────────────────────────────────────────
//
// The previous version installed a per-victim fw filter on the physical NIC's
// ingress qdisc to redirect only marked packets to ifb0.  This was wrong.
//
// WHY IT FAILED:
//   Download packets arrive at virbr1/eth0 ingress BEFORE the netfilter
//   FORWARD hook runs.  At that point the packet carries no fwmark.  The
//   fw filter never matches, nothing reaches ifb0, and download traffic is
//   unthrottled regardless of the HTB class on ifb0.
//
// THE FIX — two-stage approach matching Docs/Qos.md §7.1:
//
//   Stage 1 — physical NIC ingress (inside init()):
//     ONE catch-all filter redirects ALL ingress traffic to ifb0.
//     This runs before any conntrack / nftables hook.
//     Filter: protocol all u32 match 0 0 action connmark action mirred
//             egress redirect dev ifb0
//     The "action connmark" here restores any existing ct mark onto the skb
//     before it arrives at ifb0's qdisc.
//
//   Stage 2 — ifb0 egress (inside add_htb_leaf()):
//     By the time a packet reaches ifb0's egress qdisc, netfilter has already
//     processed it through PREROUTING (conntrack entry lookup) and the
//     harper_mangle FORWARD chain has set:
//       ip daddr <victim>  ct mark != 0  meta mark set ct mark
//     So the packet now carries the victim's slot as its fwmark.
//     The fw filter on ifb0 matches correctly and routes into the HTB class.
//
// WHAT CHANGES IN THE CODE:
//   • init(): the ingress qdisc setup adds the catch-all u32 redirect filter
//     once, covering all current and future victims.
//   • add_htb_leaf(): the per-victim ingress fw filter block is removed.
//     Only the upload (egress) fw filter on the physical NIC and the download
//     fw filter on ifb0 remain — both of these operate after conntrack.
//
// ─────────────────────────────────────────────────────────────────────────────
// HTB layout (unchanged from before)
// ─────────────────────────────────────────────────────────────────────────────
//
//  Physical NIC egress (upload):
//    root 1:  htb default 0xFFF
//    └── 1:1  ceiling the link rate
//        ├── 1:0xFFF  passthrough (all unmarked / host traffic)
//        └── 1:<slot> per-host cap  ← fw handle <slot>
//            └── sfq
//
//  Physical NIC ingress:
//    ffff:  ingress qdisc
//    └── u32 match-all → connmark restore → mirred redirect to ifb0
//        (ONE filter installed at init time, covers all victims)
//
//  ifb0 egress (download):
//    root 2:  htb default 0xFFF
//    └── 2:1  ceiling the link rate
//        ├── 2:0xFFF  passthrough (unmarked / host-destined traffic)
//        └── 2:<slot> per-host cap  ← fw handle <slot>  (mark set by nft FORWARD)
//            └── sfq

use std::collections::HashMap;
use std::net::Ipv4Addr;

use std::process::Stdio;
use tokio::io::AsyncWriteExt as _;
use tokio::process::Command;

use crate::host::table::HostId;
use crate::infra::Cleanupable;

impl Cleanupable for TcManager {
    fn cleanup(
        &mut self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), Box<dyn std::error::Error>>> + Send + '_>,
    > {
        let tc = self;
        Box::pin(async move {
            tc.cleanup().await;
            Ok(())
        })
    }
}

const IFB_DEV: &str = "ifb0";
const HANDLE_EGRESS: &str = "1:";
const HANDLE_INGRESS: &str = "2:";
const CLASS_ROOT_MINOR: u16 = 1;
const SLOT_PASSTHROUGH: u16 = 0xFFF;
const SLOT_MIN: u16 = 2;
const KERNEL_HZ: u64 = 100;
const BURST_MIN_BYTES: u64 = 1_600;
const NFT_TABLE: &str = "harper";
const NFT_CHAIN: &str = "FORWARD";

/// Single shared fwmark used by pool mode. Every victim IP is marked with this
/// so all their traffic funnels into one shared HTB class; unmarked traffic
/// (the attacker) keeps the rest of the link rate via the passthrough class.
const MARK_POOL: u32 = 0xFFE;

#[derive(Debug)]
pub struct TcError {
    pub host_id: HostId,
    pub message: String,
}

impl std::fmt::Display for TcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tc error for host {}: {}", self.host_id, self.message)
    }
}

impl std::error::Error for TcError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShapeMode {
    Limited {
        upload: Option<u64>,
        download: Option<u64>,
    },
    Blocked,
}

#[derive(Debug, Clone)]
pub struct HostSlot {
    pub slot: u16,
    pub ip: Ipv4Addr,
    pub mode: ShapeMode,
}

pub struct TcManager {
    interface: String,
    initialized: bool,
    hosts: HashMap<HostId, HostSlot>,
    next_slot: u16,
    /// Pool mode uses one static HTB class (`MARK_POOL`). It is created once and
    /// only the nftables ruleset is refreshed thereafter; never recreated.
    pool_class_created: bool,
    /// Discovered physical link rate in Mbit/s (from /sys/class/net/<iface>/speed),
    /// used for the HTB root rate and victim `ceil` values.
    line_rate_mbit: u64,
}

impl TcManager {
    pub fn new(interface: &str) -> Self {
        Self {
            interface: interface.to_string(),
            initialized: false,
            hosts: HashMap::new(),
            next_slot: SLOT_MIN,
            pool_class_created: false,
            line_rate_mbit: 1000,
        }
    }

    pub async fn init(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        for module in &["ifb", "act_mirred", "sch_htb", "sch_sfq", "cls_fw"] {
            let _ = Command::new("modprobe").arg(module).output().await;
        }

        self.line_rate_mbit = read_link_speed_mbit(&self.interface);
        println!(
            "[+] tc: link rate {} Mbit/s on {}",
            self.line_rate_mbit, self.interface
        );

        self.teardown_tc().await;
        self.teardown_nft().await;

        // IFB virtual device
        let _ = run(&["ip", "link", "add", IFB_DEV, "type", "ifb"]).await;
        run_check(&["ip", "link", "set", IFB_DEV, "up"]).await?;

        run_check(&[
            "tc",
            "qdisc",
            "add",
            "dev",
            &self.interface,
            "handle",
            "ffff:",
            "ingress",
        ])
        .await?;
        run_check(&[
            "tc",
            "filter",
            "add",
            "dev",
            &self.interface,
            "parent",
            "ffff:",
            "protocol",
            "ip",
            "u32",
            "match",
            "u32",
            "0",
            "0",
            "action",
            "connmark",
            "action",
            "mirred",
            "egress",
            "redirect",
            "dev",
            IFB_DEV,
        ])
        .await?;

        // HTB root on physical NIC (upload / egress)
        run_check(&[
            "tc",
            "qdisc",
            "add",
            "dev",
            &self.interface,
            "root",
            "handle",
            HANDLE_EGRESS,
            "htb",
            "default",
            &format!("{:x}", SLOT_PASSTHROUGH),
        ])
        .await?;
        self.add_root_classes(&self.interface.clone(), HANDLE_EGRESS)
            .await?;

        // HTB root on IFB (download / redirected ingress)
        run_check(&[
            "tc",
            "qdisc",
            "add",
            "dev",
            IFB_DEV,
            "root",
            "handle",
            HANDLE_INGRESS,
            "htb",
            "default",
            &format!("{:x}", SLOT_PASSTHROUGH),
        ])
        .await?;
        self.add_root_classes(IFB_DEV, HANDLE_INGRESS).await?;

        self.nft_create_table().await?;

        self.initialized = true;
        println!("[+] tc: initialized on {} / {}", self.interface, IFB_DEV);
        Ok(())
    }

    async fn ensure_init(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.initialized {
            self.init().await?;
        }
        Ok(())
    }

    pub async fn limit_host(
        &mut self,
        host_id: HostId,
        ip: Ipv4Addr,
        upload_kbps: Option<u64>,
        download_kbps: Option<u64>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.ensure_init().await?;

        if upload_kbps.is_none() && download_kbps.is_none() {
            return self.remove_host_inner(host_id).await;
        }

        let new_mode = if upload_kbps == Some(0) && download_kbps == Some(0) {
            ShapeMode::Blocked
        } else {
            ShapeMode::Limited {
                upload: upload_kbps,
                download: download_kbps,
            }
        };

        if let Some(existing) = self.hosts.get(&host_id).cloned() {
            match (existing.mode, new_mode) {
                (ShapeMode::Limited { .. }, ShapeMode::Limited { upload, download }) => {
                    self.update_rate_classes(existing.slot, upload, download).await?;
                    self.hosts.get_mut(&host_id).unwrap().mode = ShapeMode::Limited { upload, download };
                    println!(
                        "[*] tc: host {} ({}) updated → upload: {:?}, download: {:?}",
                        host_id, ip, upload, download
                    );
                    return Ok(());
                }
                _ => {
                    self.remove_host_inner(host_id).await?;
                }
            }
        }

        self.add_host_inner(host_id, ip, new_mode).await
    }

    pub async fn remove_host(&mut self, host_id: HostId) -> Result<(), Box<dyn std::error::Error>> {
        if !self.initialized {
            return Ok(());
        }
        self.remove_host_inner(host_id).await
    }

    pub async fn limit_range(
        &mut self,
        entries: &[(HostId, Ipv4Addr)],
        upload_kbps: Option<u64>,
        download_kbps: Option<u64>,
    ) -> Vec<TcError> {
        let mut errors = Vec::new();
        for &(id, ip) in entries {
            if let Err(e) = self.limit_host(id, ip, upload_kbps, download_kbps).await {
                errors.push(TcError {
                    host_id: id,
                    message: e.to_string(),
                });
            }
        }
        errors
    }

    /// Pool mode: every victim shares ONE HTB class of pool rates on both upload
    /// and download trees.
    pub async fn limit_pool_split(
        &mut self,
        pool_upload: Option<u64>,
        pool_download: Option<u64>,
        victim_ips: &[Ipv4Addr],
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.ensure_init().await?;

        let slot = MARK_POOL as u16;

        if !self.pool_class_created {
            match self.add_htb_leaf(slot, pool_upload, pool_download).await {
                Ok(()) => self.pool_class_created = true,
                Err(e) if e.to_string().contains("File exists") => {
                    self.pool_class_created = true;
                }
                Err(e) => return Err(e),
            }
        } else {
            self.update_rate_classes(slot, pool_upload, pool_download).await?;
        }

        let rules = build_nft_pool_rules(victim_ips, pool_upload.is_some(), pool_download.is_some());
        let _ = nft_run(&["flush", "chain", "ip", NFT_TABLE, NFT_CHAIN]).await;
        nft_apply(&ruleset_for(&rules)).await?;

        println!(
            "[+] tc: {} victim(s) share a pool (upload: {:?}, download: {:?}).",
            victim_ips.len(),
            pool_upload,
            pool_download
        );
        Ok(())
    }

    pub async fn limit_pool(
        &mut self,
        pool_kbps: u64,
        victim_ips: &[Ipv4Addr],
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.limit_pool_split(Some(pool_kbps), Some(pool_kbps), victim_ips).await
    }

    pub fn is_shaping(&self, host_id: HostId) -> bool {
        self.hosts.contains_key(&host_id)
    }

    pub fn current_kbps(&self, host_id: HostId) -> Option<u64> {
        self.hosts.get(&host_id).map(|s| match s.mode {
            ShapeMode::Limited { upload, download } => upload.or(download).unwrap_or(0),
            ShapeMode::Blocked => 0,
        })
    }

    pub async fn cleanup(&mut self) {
        if !self.initialized {
            return;
        }
        self.teardown_tc().await;
        self.teardown_nft().await;
        self.hosts.clear();
        self.initialized = false;
        self.pool_class_created = false;
        println!("[+] tc: cleanup complete — network state restored");
    }
}

// Drop intentionally omitted — cleanup() is async and callers must call it
// explicitly. The old sync Drop impl can't be maintained with async teardown.
// Both main.rs and gateway_mode.rs already call cleanup() on shutdown.

impl TcManager {
    fn alloc_slot(&mut self) -> u16 {
        loop {
            let s = self.next_slot;
            self.next_slot = if self.next_slot >= u16::MAX - 1 {
                SLOT_MIN
            } else {
                self.next_slot + 1
            };
            if s != CLASS_ROOT_MINOR && s != SLOT_PASSTHROUGH {
                return s;
            }
        }
    }

    async fn add_root_classes(
        &self,
        dev: &str,
        handle: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let major = handle.trim_end_matches(':');
        let root_class = format!("{}:1", major);
        let pass_class = format!("{}:{:x}", major, SLOT_PASSTHROUGH);
        let line_rate = self.line_rate_str();

        run_check(&[
            "tc",
            "class",
            "add",
            "dev",
            dev,
            "parent",
            handle,
            "classid",
            &root_class,
            "htb",
            "rate",
            line_rate.as_str(),
            "ceil",
            line_rate.as_str(),
        ])
        .await?;
        run_check(&[
            "tc",
            "class",
            "add",
            "dev",
            dev,
            "parent",
            &root_class,
            "classid",
            &pass_class,
            "htb",
            "rate",
            line_rate.as_str(),
            "ceil",
            line_rate.as_str(),
        ])
        .await?;
        Ok(())
    }

    /// Pure state mutation: record a host's shaping slot without touching the
    /// kernel. Extracted from `add_host_inner` so the slot-allocation and map
    /// update can be asserted root-free (e.g. BDD tests call this directly).
    /// Reuses the existing slot when the host is already shaped (mirrors the
    /// Limited→Limited update path in `limit_host`), otherwise allocates fresh.
    pub(crate) fn apply_host_slot(
        &mut self,
        host_id: HostId,
        ip: Ipv4Addr,
        mode: ShapeMode,
    ) -> u16 {
        let slot = match self.hosts.get(&host_id) {
            Some(existing) => existing.slot,
            None => self.alloc_slot(),
        };
        self.hosts.insert(host_id, HostSlot { slot, ip, mode });
        slot
    }

    async fn add_host_inner(
        &mut self,
        host_id: HostId,
        ip: Ipv4Addr,
        mode: ShapeMode,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let slot = self.apply_host_slot(host_id, ip, mode);

        let (up, down) = match mode {
            ShapeMode::Limited { upload, download } => (upload, download),
            ShapeMode::Blocked => (Some(0), Some(0)),
        };
        self.add_htb_leaf(slot, up, down).await?;
        self.nft_rebuild_chain().await?;

        match mode {
            ShapeMode::Limited { upload, download } => {
                println!(
                    "[+] tc: host {} ({}) limited → upload: {:?}, download: {:?}",
                    host_id, ip, upload, download
                )
            }
            ShapeMode::Blocked => println!("[+] tc: host {} ({}) BLOCKED", host_id, ip),
        }
        Ok(())
    }

    /// Pure state mutation: drop a host's shaping slot without touching the
    /// kernel. Extracted from `remove_host_inner` so the state clear can be
    /// asserted root-free (e.g. BDD tests call this directly).
    pub(crate) fn clear_host_slot(&mut self, host_id: HostId) -> bool {
        self.hosts.remove(&host_id).is_some()
    }

    async fn remove_host_inner(
        &mut self,
        host_id: HostId,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let info = match self.hosts.remove(&host_id) {
            Some(s) => s,
            None => return Ok(()),
        };
        self.clear_host_slot(host_id);
        self.remove_htb_leaf(info.slot).await;
        self.nft_rebuild_chain().await?;
        println!("[+] tc: shaping removed for host {}", host_id);
        Ok(())
    }

    async fn add_htb_leaf(
        &self,
        slot: u16,
        upload_kbps: Option<u64>,
        download_kbps: Option<u64>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let slot_hex = format!("{:x}", slot);
        let slot_str = format!("{}", slot);
        let line_rate = self.line_rate_str();

        if let Some(up) = upload_kbps {
            let rate_str = if up == 0 {
                "1bit".to_string()
            } else {
                format!("{}kbit", up)
            };
            let burst = burst_for(up);
            let dev = self.interface.as_str();
            let major = HANDLE_EGRESS.trim_end_matches(':');
            let root_class = format!("{}:1", major);
            let classid = format!("{}:{}", major, slot_hex);
            let leaf_handle = format!("{:x}:", slot as u32 + 0x100);

            if let Err(e) = run(&[
                "tc",
                "class",
                "add",
                "dev",
                dev,
                "parent",
                &root_class,
                "classid",
                &classid,
                "htb",
                "rate",
                &rate_str,
                "ceil",
                line_rate.as_str(),
                "burst",
                &burst,
            ])
            .await {
                if !e.to_string().contains("File exists") {
                    return Err(format!("tc class add failed: {}", e).into());
                }
            }
            
            run_check(&[
                "tc",
                "qdisc",
                "add",
                "dev",
                dev,
                "parent",
                &classid,
                "handle",
                &leaf_handle,
                "sfq",
                "perturb",
                "10",
            ])
            .await?;
            run_check(&[
                "tc",
                "filter",
                "add",
                "dev",
                dev,
                "parent",
                &format!("{}:0", major),
                "protocol",
                "ip",
                "handle",
                &slot_str,
                "fw",
                "flowid",
                &classid,
            ])
            .await?;
        }

        if let Some(down) = download_kbps {
            let rate_str = if down == 0 {
                "1bit".to_string()
            } else {
                format!("{}kbit", down)
            };
            let burst = burst_for(down);
            let dev = IFB_DEV;
            let major = HANDLE_INGRESS.trim_end_matches(':');
            let root_class = format!("{}:1", major);
            let classid = format!("{}:{}", major, slot_hex);
            let leaf_handle = format!("{:x}:", slot as u32 + 0x200);

            if let Err(e) = run(&[
                "tc",
                "class",
                "add",
                "dev",
                dev,
                "parent",
                &root_class,
                "classid",
                &classid,
                "htb",
                "rate",
                &rate_str,
                "ceil",
                line_rate.as_str(),
                "burst",
                &burst,
            ])
            .await {
                if !e.to_string().contains("File exists") {
                    return Err(format!("tc class add failed: {}", e).into());
                }
            }

            run_check(&[
                "tc",
                "qdisc",
                "add",
                "dev",
                dev,
                "parent",
                &classid,
                "handle",
                &leaf_handle,
                "sfq",
                "perturb",
                "10",
            ])
            .await?;
            run_check(&[
                "tc",
                "filter",
                "add",
                "dev",
                dev,
                "parent",
                &format!("{}:0", major),
                "protocol",
                "ip",
                "handle",
                &slot_str,
                "fw",
                "flowid",
                &classid,
            ])
            .await?;
        }

        Ok(())
    }

    async fn remove_htb_leaf(&self, slot: u16) {
        for (dev, tree) in [
            (self.interface.as_str(), HANDLE_EGRESS),
            (IFB_DEV, HANDLE_INGRESS),
        ] {
            let major = tree.trim_end_matches(':');
            let classid = format!("{}:{:x}", major, slot);
            let leaf_handle = format!("{:x}:", slot as u32 + 0x100);
            
            // Try to remove, but don't care if it fails (e.g. doesn't exist)
            let _ = run(&[
                "tc",
                "qdisc",
                "del",
                "dev",
                dev,
                "parent",
                &classid,
                "handle",
                &leaf_handle,
            ])
            .await;
            
            if let Err(e) = run(&["tc", "class", "del", "dev", dev, "classid", &classid]).await {
                println!("[*] tc: warning: failed to remove class {}: {}", classid, e);
            }
        }
    }

    async fn update_rate_classes(
        &self,
        slot: u16,
        upload_kbps: Option<u64>,
        download_kbps: Option<u64>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.remove_htb_leaf(slot).await;
        self.add_htb_leaf(slot, upload_kbps, download_kbps).await
    }

    async fn teardown_tc(&self) {
        let _ = run(&["tc", "qdisc", "del", "dev", &self.interface, "root"]).await;
        let _ = run(&["tc", "qdisc", "del", "dev", &self.interface, "ingress"]).await;
        let _ = run(&["tc", "qdisc", "del", "dev", IFB_DEV, "root"]).await;
        let _ = run(&["ip", "link", "set", IFB_DEV, "down"]).await;
        let _ = run(&["ip", "link", "del", IFB_DEV]).await;
    }
}

impl TcManager {
    async fn nft_create_table(&self) -> Result<(), Box<dyn std::error::Error>> {
        let ruleset = format!(
            "table ip {table} {{\n\
             \tchain {chain} {{\n\
             \t\ttype filter hook forward priority mangle; policy accept;\n\
             \t}}\n\
             }}",
            table = NFT_TABLE,
            chain = NFT_CHAIN,
        );
        nft_apply(&ruleset).await
    }

    async fn nft_rebuild_chain(&self) -> Result<(), Box<dyn std::error::Error>> {
        let rules = build_nft_rules(&self.hosts);
        let _ = nft_run(&["flush", "chain", "ip", NFT_TABLE, NFT_CHAIN]).await;
        nft_apply(&ruleset_for(&rules)).await
    }

    async fn teardown_nft(&self) {
        let _ = nft_run(&["delete", "table", "ip", NFT_TABLE]).await;
    }
}

/// Builds the nftables FORWARD-chain rule body for per-host shaping. Pure and
/// testable — no external commands. `hosts` maps each HostId to its slot/mode.
pub(crate) fn build_nft_rules(hosts: &HashMap<HostId, HostSlot>) -> String {
    let mut rules = String::new();

    for slot_info in hosts.values() {
        let ip = slot_info.ip.to_string();
        let mark = slot_info.slot as u32;

        match slot_info.mode {
            ShapeMode::Limited { upload, download } => {
                if upload.is_some() {
                    rules.push_str(&format!(
                        "\t\tip saddr {ip} meta mark set {mark} ct mark set meta mark\n"
                    ));
                }
                if download.is_some() {
                    rules.push_str(&format!(
                        "\t\tip daddr {ip} ct mark != 0 meta mark set ct mark\n\
                         \t\tip daddr {ip} ct mark == 0 meta mark set {mark} ct mark set meta mark\n"
                    ));
                }
            }
            ShapeMode::Blocked => {
                rules.push_str(&format!(
                    "\t\tip saddr {ip} drop\n\
                     \t\tip daddr {ip} drop\n"
                ));
            }
        }
    }

    rules
}

/// Builds the nftables FORWARD-chain rule body for pool mode: every victim IP
/// is marked with the single shared `MARK_POOL` so all its traffic funnels
/// into one shared HTB class. Pure and testable.
pub(crate) fn build_nft_pool_rules(victim_ips: &[Ipv4Addr], has_upload: bool, has_download: bool) -> String {
    let mut rules = String::new();
    let mark = MARK_POOL;

    for ip in victim_ips {
        let ip = ip.to_string();
        if has_upload {
            rules.push_str(&format!(
                "\t\tip saddr {ip} meta mark set {mark} ct mark set meta mark\n"
            ));
        }
        if has_download {
            rules.push_str(&format!(
                "\t\tip daddr {ip} ct mark != 0 meta mark set ct mark\n\
                 \t\tip daddr {ip} ct mark == 0 meta mark set {mark} ct mark set meta mark\n"
            ));
        }
    }

    rules
}

/// Wraps a rule body in a complete nftables table/chain ruleset string.
fn ruleset_for(rules: &str) -> String {
    format!(
        "table ip {table} {{\n\
         \tchain {chain} {{\n\
         \t\ttype filter hook forward priority mangle; policy accept;\n\
         {rules}\
         \t}}\n\
         }}",
        table = NFT_TABLE,
        chain = NFT_CHAIN,
        rules = rules,
    )
}

/// Reads the interface's reported link speed in Mbit/s from
/// `/sys/class/net/<iface>/speed`. Returns `None` (caller falls back to 1000)
/// when the file is unreadable (e.g. virtual/IFB devices) or reports the
/// kernel's "unknown speed" sentinel.
fn read_link_speed_mbit(interface: &str) -> u64 {
    let path = format!("/sys/class/net/{interface}/speed");
    match std::fs::read_to_string(&path) {
        Ok(s) => s
            .trim()
            .parse::<u64>()
            .ok()
            .filter(|&v| v >= 1 && v <= 1_000_000)
            .unwrap_or(1000),
        Err(_) => 1000,
    }
}

impl TcManager {
    /// Formats the discovered link rate as an `tc` rate string (e.g. "1000mbit").
    fn line_rate_str(&self) -> String {
        format!("{}mbit", self.line_rate_mbit)
    }
}

pub(crate) fn burst_for(kbps: u64) -> String {
    if kbps == 0 {
        return format!("{}b", BURST_MIN_BYTES);
    }
    let rate_bps = kbps * 1_000 / 8;
    let minimum = rate_bps / KERNEL_HZ;
    let burst_bytes = minimum.max(BURST_MIN_BYTES);
    format!("{}b", burst_bytes)
}

async fn run(args: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    let (prog, rest) = args.split_first().ok_or("empty command")?;
    let out = Command::new(prog).args(rest).output().await?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(String::from_utf8_lossy(&out.stderr)
            .trim()
            .to_string()
            .into())
    }
}

async fn run_check(args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    run(args)
        .await
        .map(|_| ())
        .map_err(|e| format!("{} failed: {}", args.join(" "), e).into())
}

async fn nft_run(args: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    let mut full = vec!["nft"];
    full.extend_from_slice(args);
    run(&full).await
}

async fn nft_apply(ruleset: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("nft -f - spawn: {e}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(ruleset.as_bytes())
            .await
            .map_err(|e| format!("nft stdin write: {e}"))?;
    }

    let out = child
        .wait_with_output()
        .await
        .map_err(|e| format!("nft -f - wait: {e}"))?;

    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "nft -f - failed: {}\nRuleset:\n{}",
            String::from_utf8_lossy(&out.stderr).trim(),
            ruleset,
        )
        .into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_burst_zero_returns_floor() {
        let n: u64 = burst_for(0).trim_end_matches('b').parse().unwrap();
        assert_eq!(n, BURST_MIN_BYTES);
    }

    #[test]
    fn test_burst_floor_at_low_rate() {
        let n: u64 = burst_for(1).trim_end_matches('b').parse().unwrap();
        assert!(n >= BURST_MIN_BYTES);
    }

    #[test]
    fn test_burst_exceeds_htb_minimum_1mbit() {
        let kbps = 1_000u64;
        let min = (kbps * 1_000 / 8) / KERNEL_HZ;
        let n: u64 = burst_for(kbps).trim_end_matches('b').parse().unwrap();
        assert!(n >= min);
    }

    #[test]
    fn test_burst_ends_with_b() {
        for kbps in [0, 1, 100, 1_000, 10_000] {
            assert!(burst_for(kbps).ends_with('b'));
        }
    }

    #[test]
    fn test_burst_monotone() {
        let b1: u64 = burst_for(10_000).trim_end_matches('b').parse().unwrap();
        let b2: u64 = burst_for(100_000).trim_end_matches('b').parse().unwrap();
        assert!(b2 > b1);
    }

    fn make() -> TcManager {
        TcManager::new("eth0")
    }

    #[test]
    fn test_alloc_slot_avoids_reserved() {
        let mut m = make();
        for _ in 0..200 {
            let s = m.alloc_slot();
            assert_ne!(s, CLASS_ROOT_MINOR);
            assert_ne!(s, SLOT_PASSTHROUGH);
        }
    }

    #[test]
    fn test_alloc_slot_unique() {
        let mut m = make();
        let slots: Vec<u16> = (0..50).map(|_| m.alloc_slot()).collect();
        let set: std::collections::HashSet<u16> = slots.iter().copied().collect();
        assert_eq!(set.len(), slots.len());
    }

    #[test]
    fn test_new_is_empty() {
        let m = make();
        assert!(!m.initialized);
        assert!(!m.is_shaping(1));
        assert_eq!(m.current_kbps(1), None);
    }

    fn insert(m: &mut TcManager, id: HostId, ip: Ipv4Addr, mode: ShapeMode) {
        let slot = m.alloc_slot();
        m.hosts.insert(id, HostSlot { slot, ip, mode });
    }

    #[test]
    fn test_current_kbps_limited() {
        let mut m = make();
        insert(
            &mut m,
            1,
            Ipv4Addr::new(10, 0, 0, 1),
            ShapeMode::Limited { upload: Some(2_048), download: Some(2_048) },
        );
        assert_eq!(m.current_kbps(1), Some(2_048));
    }

    #[test]
    fn test_current_kbps_blocked() {
        let mut m = make();
        insert(&mut m, 1, Ipv4Addr::new(10, 0, 0, 1), ShapeMode::Blocked);
        assert_eq!(m.current_kbps(1), Some(0));
    }

    #[tokio::test]
    async fn test_cleanup_uninit_noop() {
        let mut m = make();
        m.cleanup().await;
        assert!(!m.initialized);
    }

    #[tokio::test]
    async fn test_cleanup_twice_safe() {
        let mut m = make();
        m.cleanup().await;
        m.cleanup().await;
    }

    #[tokio::test]
    async fn test_batch_empty_no_errors() {
        let mut m = make();
        m.initialized = true;
        assert!(m.limit_range(&[], Some(1_000), Some(1_000)).await.is_empty());
    }

    #[test]
    fn test_shape_mode_eq() {
        assert_eq!(
            ShapeMode::Limited { upload: Some(100), download: Some(100) },
            ShapeMode::Limited { upload: Some(100), download: Some(100) }
        );
        assert_ne!(
            ShapeMode::Limited { upload: Some(100), download: Some(100) },
            ShapeMode::Limited { upload: Some(200), download: Some(200) }
        );
        assert_ne!(
            ShapeMode::Limited { upload: Some(100), download: Some(100) },
            ShapeMode::Blocked
        );
    }

    #[test]
    fn test_build_nft_rules_per_host_mark() {
        let mut hosts = HashMap::new();
        hosts.insert(
            1,
            HostSlot {
                slot: 7,
                ip: Ipv4Addr::new(10, 0, 0, 5),
                mode: ShapeMode::Limited { upload: Some(2_048), download: Some(2_048) },
            },
        );
        let rules = build_nft_rules(&hosts);
        // Upload mark + two download rules, all using the slot (7) as the mark.
        assert!(rules.contains("ip saddr 10.0.0.5 meta mark set 7"));
        assert!(rules.contains("ip daddr 10.0.0.5 ct mark == 0 meta mark set 7"));
        assert!(ruleset_for(&rules).contains("type filter hook forward priority mangle"));
    }

    #[test]
    fn test_build_nft_rules_blocked_drops() {
        let mut hosts = HashMap::new();
        hosts.insert(
            1,
            HostSlot {
                slot: 9,
                ip: Ipv4Addr::new(10, 0, 0, 9),
                mode: ShapeMode::Blocked,
            },
        );
        let rules = build_nft_rules(&hosts);
        assert!(rules.contains("ip saddr 10.0.0.9 drop"));
        assert!(rules.contains("ip daddr 10.0.0.9 drop"));
    }

    #[test]
    fn test_build_nft_pool_rules_single_shared_mark() {
        let victims = vec![Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 0, 6)];
        let rules = build_nft_pool_rules(&victims, true, true);
        // Both victims marked with the SAME shared mark (MARK_POOL = 0xFFE = 4094).
        assert!(rules.contains("ip saddr 10.0.0.5 meta mark set 4094"));
        assert!(rules.contains("ip saddr 10.0.0.6 meta mark set 4094"));
        assert!(rules.contains("ip daddr 10.0.0.5 ct mark == 0 meta mark set 4094"));
        assert!(rules.contains("ip daddr 10.0.0.6 ct mark == 0 meta mark set 4094"));
        // No per-host slot numbers — every line uses 4094.
        assert!(!rules.contains("meta mark set 7"));
    }

    #[tokio::test]
    #[ignore]
    async fn test_live_full_cycle() {
        let mut m = TcManager::new("lo");
        m.init().await.unwrap();
        m.limit_host(1, Ipv4Addr::new(127, 0, 0, 1), Some(1_000), Some(1_000))
            .await
            .unwrap();
        assert_eq!(m.current_kbps(1), Some(1_000));
        m.remove_host(1).await.unwrap();
        assert!(!m.is_shaping(1));
        m.cleanup().await;
    }
}
