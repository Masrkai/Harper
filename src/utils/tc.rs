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
//    └── 1:1  ceiling LINE_RATE
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
//    └── 2:1  ceiling LINE_RATE
//        ├── 2:0xFFF  passthrough (unmarked / host-destined traffic)
//        └── 2:<slot> per-host cap  ← fw handle <slot>  (mark set by nft FORWARD)
//            └── sfq

use std::collections::HashMap;
use std::net::Ipv4Addr;

use tokio::io::AsyncWriteExt as _;
use std::process::Stdio;
use tokio::process::Command;

use crate::host::table::HostId;
use crate::infra::Cleanupable;

impl Cleanupable for TcManager {
    fn cleanup(&mut self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Box<dyn std::error::Error>>> + Send + '_>> {
        let tc = self;
        Box::pin(async move {
            tc.cleanup().await;
            Ok(())
        })
    }
}

const IFB_DEV: &str = "ifb0";
const LINE_RATE: &str = "1000mbit";
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
/// (the attacker) keeps the rest of LINE_RATE via the passthrough class.
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
    Limited(u64),
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
}

impl TcManager {
    pub fn new(interface: &str) -> Self {
        Self {
            interface: interface.to_string(),
            initialized: false,
            hosts: HashMap::new(),
            next_slot: SLOT_MIN,
        }
    }

    pub async fn init(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        for module in &["ifb", "act_mirred", "sch_htb", "sch_sfq", "cls_fw"] {
            let _ = Command::new("modprobe").arg(module).output().await;
        }

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
        ]).await?;
        run_check(&[
            "tc",
            "filter",
            "add",
            "dev",
            &self.interface,
            "parent",
            "ffff:",
            "protocol",
            "all",
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
        ]).await?;

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
        ]).await?;
        self.add_root_classes(&self.interface.clone(), HANDLE_EGRESS).await?;

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
        ]).await?;
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
        kbps: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.ensure_init().await?;

        let new_mode = if kbps == 0 {
            ShapeMode::Blocked
        } else {
            ShapeMode::Limited(kbps)
        };

        if let Some(existing) = self.hosts.get(&host_id).cloned() {
            match (existing.mode, new_mode) {
                (ShapeMode::Limited(_), ShapeMode::Limited(new_kbps)) => {
                    self.update_rate_classes(existing.slot, new_kbps).await?;
                    self.hosts.get_mut(&host_id).unwrap().mode = ShapeMode::Limited(new_kbps);
                    println!(
                        "[*] tc: host {} ({}) updated → {} kbps",
                        host_id, ip, new_kbps
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

    pub async fn limit_range(&mut self, entries: &[(HostId, Ipv4Addr)], kbps: u64) -> Vec<TcError> {
        let mut errors = Vec::new();
        for &(id, ip) in entries {
            if let Err(e) = self.limit_host(id, ip, kbps).await {
                errors.push(TcError {
                    host_id: id,
                    message: e.to_string(),
                });
            }
        }
        errors
    }

    /// Pool mode: every victim shares ONE HTB class of `pool_kbps` on both the
    /// upload (egress) and download (ifb0) trees. All victim IPs are marked
    /// with the single shared `MARK_POOL` fwmark so their traffic funnels into
    /// that class; unmarked traffic (the attacker) keeps the rest of
    /// `LINE_RATE` via the passthrough default class.
    pub async fn limit_pool(
        &mut self,
        pool_kbps: u64,
        victim_ips: &[Ipv4Addr],
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.ensure_init().await?;

        let slot = MARK_POOL as u16;
        // Recreate the shared class idempotently.
        self.remove_htb_leaf(slot).await;
        self.add_htb_leaf(slot, pool_kbps).await?;

        let rules = build_nft_pool_rules(victim_ips);
        let _ = nft_run(&["flush", "chain", "ip", NFT_TABLE, NFT_CHAIN]).await;
        nft_apply(&ruleset_for(&rules)).await?;

        println!(
            "[+] tc: {} victim(s) share a {} kbit pool (attacker keeps the rest).",
            victim_ips.len(),
            pool_kbps
        );
        Ok(())
    }

    pub fn is_shaping(&self, host_id: HostId) -> bool {
        self.hosts.contains_key(&host_id)
    }

    pub fn current_kbps(&self, host_id: HostId) -> Option<u64> {
        self.hosts.get(&host_id).map(|s| match s.mode {
            ShapeMode::Limited(k) => k,
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

    async fn add_root_classes(&self, dev: &str, handle: &str) -> Result<(), Box<dyn std::error::Error>> {
        let major = handle.trim_end_matches(':');
        let root_class = format!("{}:1", major);
        let pass_class = format!("{}:{:x}", major, SLOT_PASSTHROUGH);

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
            LINE_RATE,
        ]).await?;
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
            LINE_RATE,
        ]).await?;
        Ok(())
    }

    async fn add_host_inner(
        &mut self,
        host_id: HostId,
        ip: Ipv4Addr,
        mode: ShapeMode,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let slot = self.alloc_slot();
        self.hosts.insert(host_id, HostSlot { slot, ip, mode });

        let kbps = match mode {
            ShapeMode::Limited(k) => k,
            ShapeMode::Blocked => 0,
        };
        self.add_htb_leaf(slot, kbps).await?;
        self.nft_rebuild_chain().await?;

        match mode {
            ShapeMode::Limited(k) => {
                println!("[+] tc: host {} ({}) limited to {} kbps", host_id, ip, k)
            }
            ShapeMode::Blocked => println!("[+] tc: host {} ({}) BLOCKED", host_id, ip),
        }
        Ok(())
    }

    async fn remove_host_inner(&mut self, host_id: HostId) -> Result<(), Box<dyn std::error::Error>> {
        let info = match self.hosts.remove(&host_id) {
            Some(s) => s,
            None => return Ok(()),
        };
        self.remove_htb_leaf(info.slot).await;
        self.nft_rebuild_chain().await?;
        println!("[+] tc: shaping removed for host {}", host_id);
        Ok(())
    }

    async fn add_htb_leaf(&self, slot: u16, kbps: u64) -> Result<(), Box<dyn std::error::Error>> {
        let rate_str = if kbps == 0 {
            "1bit".to_string()
        } else {
            format!("{}kbit", kbps)
        };
        let burst = burst_for(kbps);
        let slot_hex = format!("{:x}", slot);
        let slot_str = format!("{}", slot);

        // ── Upload: HTB class + fw filter on physical NIC egress ─────────────
        //
        // The nftables FORWARD chain sets:
        //   ip saddr <victim>  meta mark set <slot>  ct mark set meta mark
        // so upload packets carry the mark by the time they reach this egress
        // qdisc.  The fw filter matches and routes into the limited HTB class.
        {
            let dev = self.interface.as_str();
            let major = HANDLE_EGRESS.trim_end_matches(':');
            let root_class = format!("{}:1", major);
            let classid = format!("{}:{}", major, slot_hex);
            let leaf_handle = format!("{:x}:", slot as u32 + 0x100);

            run_check(&[
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
                &rate_str,
                "burst",
                &burst,
            ]).await?;
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
            ]).await?;
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
            ]).await?;
        }

        // ── NO per-victim ingress filter here ─────────────────────────────────
        //
        // The catch-all redirect (u32 match 0 0) installed once in init()
        // sends ALL ingress traffic to ifb0.  We do not add anything to the
        // physical NIC's ingress qdisc per-victim.

        // ── Download: HTB class + fw filter on IFB egress ────────────────────
        //
        // By the time a packet lands on ifb0's egress qdisc it has been
        // through PREROUTING (conntrack lookup) and the nftables FORWARD chain:
        //   ip daddr <victim>  ct mark != 0  meta mark set ct mark
        // The mark is now set, and the fw filter below classifies it into the
        // correct rate-limited HTB class.
        {
            let dev = IFB_DEV;
            let major = HANDLE_INGRESS.trim_end_matches(':');
            let root_class = format!("{}:1", major);
            let classid = format!("{}:{}", major, slot_hex);
            let leaf_handle = format!("{:x}:", slot as u32 + 0x200);

            run_check(&[
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
                &rate_str,
                "burst",
                &burst,
            ]).await?;
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
            ]).await?;
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
            ]).await?;
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
            ]).await;
            let _ = run(&["tc", "class", "del", "dev", dev, "classid", &classid]).await;
        }
    }

    async fn update_rate_classes(&self, slot: u16, kbps: u64) -> Result<(), Box<dyn std::error::Error>> {
        let rate_str = format!("{}kbit", kbps);
        let burst = burst_for(kbps);

        for (dev, tree) in [
            (self.interface.as_str(), HANDLE_EGRESS),
            (IFB_DEV, HANDLE_INGRESS),
        ] {
            let major = tree.trim_end_matches(':');
            let root_class = format!("{}:1", major);
            let classid = format!("{}:{:x}", major, slot);

            run_check(&[
                "tc",
                "class",
                "change",
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
                &rate_str,
                "burst",
                &burst,
            ]).await?;
        }
        Ok(())
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
            ShapeMode::Limited(_) => {
                // Upload:   mark packet + save to conntrack entry.
                // Download: restore mark from conntrack, or set it on the
                // first download packet (ct mark 0) so it reaches the class.
                rules.push_str(&format!(
                    "\t\tip saddr {ip} meta mark set {mark} ct mark set meta mark\n\
                     \t\tip daddr {ip} ct mark != 0 meta mark set ct mark\n\
                     \t\tip daddr {ip} ct mark == 0 meta mark set {mark} ct mark set meta mark\n"
                ));
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
pub(crate) fn build_nft_pool_rules(victim_ips: &[Ipv4Addr]) -> String {
    let mut rules = String::new();
    let mark = MARK_POOL;

    for ip in victim_ips {
        let ip = ip.to_string();
        rules.push_str(&format!(
            "\t\tip saddr {ip} meta mark set {mark} ct mark set meta mark\n\
             \t\tip daddr {ip} ct mark != 0 meta mark set ct mark\n\
             \t\tip daddr {ip} ct mark == 0 meta mark set {mark} ct mark set meta mark\n"
        ));
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
            ShapeMode::Limited(2_048),
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
        assert!(m.limit_range(&[], 1_000).await.is_empty());
    }

    #[test]
    fn test_shape_mode_eq() {
        assert_eq!(ShapeMode::Limited(100), ShapeMode::Limited(100));
        assert_ne!(ShapeMode::Limited(100), ShapeMode::Limited(200));
        assert_ne!(ShapeMode::Limited(100), ShapeMode::Blocked);
    }

    #[test]
    fn test_build_nft_rules_per_host_mark() {
        let mut hosts = HashMap::new();
        hosts.insert(
            1,
            HostSlot {
                slot: 7,
                ip: Ipv4Addr::new(10, 0, 0, 5),
                mode: ShapeMode::Limited(2_048),
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
        let victims = vec![
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(10, 0, 0, 6),
        ];
        let rules = build_nft_pool_rules(&victims);
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
        m.limit_host(1, Ipv4Addr::new(127, 0, 0, 1), 1_000).await.unwrap();
        assert_eq!(m.current_kbps(1), Some(1_000));
        m.remove_host(1).await.unwrap();
        assert!(!m.is_shaping(1));
        m.cleanup().await;
    }
}
