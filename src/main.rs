// src/main.rs
mod cli;
mod forwarder;
mod gateway_mode;
mod host;
mod network;
mod spoofer;
mod utils;

use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::RwLock;

use clap::Parser;

use network::calculator::get_cidr;
use network::scanner::ArpScanner;

use cli::color::Color;
use cli::selector::InterfaceSelector;
use cli::target_selector::TargetSelector;

use forwarder::engine::PacketForwarder;
use forwarder::{ForwardRule, ForwarderCommand};

use host::table::{HostState, HostTable};

use spoofer::{SpoofTarget, SpooferCommand, SpooferEngine};

use utils::check_root::check_root;
use utils::gateway::get_gateway;
use utils::logger::Logger;
use utils::oui::lookup_vendor;
use utils::tc::TcManager;

const COLOR_OK:      Color = Color::from_hex(b"#50C878");
const COLOR_WARN:    Color = Color::from_hex(b"#FFB347");
const COLOR_KEYWORD: Color = Color::from_hex(b"#C792EA");

// ─────────────────────────────────────────────────────────────────────────────
// CLI
// ─────────────────────────────────────────────────────────────────────────────

/// harper — ARP spoofer / bandwidth limiter
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short, long, value_name = "IFACE")]
    interface: Option<String>,

    /// Default gateway IP (MITM mode only — autodetected if omitted).
    #[arg(short, long, value_name = "IP")]
    gateway: Option<Ipv4Addr>,

    /// Target IP(s) or CIDR ranges — skips full ARP scan (MITM mode only).
    #[arg(short, long = "target", value_name = "IP|CIDR|RANGE")]
    targets: Vec<String>,

    /// Bandwidth cap in kbps.
    /// MITM mode: 0 = block entirely, omit = unlimited.
    /// Gateway mode: applied to each selected client, omit = unlimited.
    #[arg(short, long, value_name = "KBPS")]
    bandwidth: Option<u64>,

    /// Gateway mode: shape clients on a hotspot or LAN you host.
    ///
    /// No ARP poisoning is performed — the kernel already routes traffic
    /// through this machine because you are the actual gateway / AP.
    /// Only tc HTB shaping is applied.
    ///
    /// Incompatible with --target and --gateway.
    #[arg(long, default_value_t = false)]
    gateway_mode: bool,

    /// Use one-sided MITM (gratuitous ARP takeover instead of bidirectional poisoning).
    /// Recommended for ethernet networks with strict ARP protection.
    #[arg(long, default_value_t = false)]
    one_sided: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Kernel state (MITM mode only)
// ─────────────────────────────────────────────────────────────────────────────

struct KernelState {
    ip_forward: String,
    send_redirects: String,
    rp_filter_all: String,
    interface: String,
}

impl KernelState {
    fn enable(interface: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let redirect_path = format!("/proc/sys/net/ipv4/conf/{}/send_redirects", interface);

        let state = Self {
            ip_forward: read_proc("/proc/sys/net/ipv4/ip_forward"),
            send_redirects: read_proc(&redirect_path),
            rp_filter_all: read_proc("/proc/sys/net/ipv4/conf/all/rp_filter"),
            interface: interface.to_owned(),
        };

        // IMPORTANT: set ip_forward to 0, NOT 1.
        //
        // harper's PacketForwarder handles all relaying in userspace by
        // receiving packets addressed to our MAC, rewriting the Ethernet
        // header, and re-sending them.  If we also enable kernel IP
        // forwarding, the kernel forwards every packet a second time,
        // creating duplicate packets.  Those duplicates cause TCP to see
        // out-of-order segments, trigger spurious retransmits, and make
        // connections stall until one forwarding path "wins" — which is the
        // unstable behaviour seen before this fix.
        //
        // With ip_forward=0 only our userspace forwarder relays traffic.
        // The kernel still processes packets addressed directly to our IP
        // (e.g. SSH into this machine) — that path is unaffected by
        // ip_forward.  Only transit traffic (victim ↔ gateway) is affected,
        // and that is exactly what PacketForwarder handles.
        std::fs::write("/proc/sys/net/ipv4/ip_forward", "0\n")?;

        let _ = std::fs::write(&redirect_path, "0\n");
        let _ = std::fs::write("/proc/sys/net/ipv4/conf/all/send_redirects", "0\n");

        // rp_filter must still be 0 — reverse-path filtering would drop
        // forwarded packets whose source IP is on the same interface they
        // arrived on (which is always the case in a same-segment MITM).
        std::fs::write("/proc/sys/net/ipv4/conf/all/rp_filter", "0\n")?;
        let _ = std::fs::write(
            &format!("/proc/sys/net/ipv4/conf/{}/rp_filter", interface),
            "0\n",
        );

        Ok(state)
    }

    fn restore(&self) {
        let redirect_path = format!("/proc/sys/net/ipv4/conf/{}/send_redirects", self.interface);
        let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", &self.ip_forward);
        let _ = std::fs::write(&redirect_path, &self.send_redirects);
        let _ = std::fs::write("/proc/sys/net/ipv4/conf/all/send_redirects", "1\n");
        let _ = std::fs::write("/proc/sys/net/ipv4/conf/all/rp_filter", &self.rp_filter_all);
        let _ = std::fs::write(
            &format!("/proc/sys/net/ipv4/conf/{}/rp_filter", self.interface),
            &self.rp_filter_all,
        );
    }
}

fn read_proc(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|_| "0\n".to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// NixOS rpfilter gate (MITM mode only)
// ─────────────────────────────────────────────────────────────────────────────

struct NftGate {
    rpfilter_handle: Option<u64>,
}

impl NftGate {
    fn install(interface: &str) -> Self {
        let rule = format!(
            "add rule inet nixos-fw rpfilter-allow iifname \"{iface}\" accept",
            iface = interface,
        );

        let ok = std::process::Command::new("nft")
            .args(rule.split_whitespace())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        if !ok {
            println!("[!] nft: could not add rpfilter-allow rule (may be harmless)");
            return Self {
                rpfilter_handle: None,
            };
        }

        let handle = last_rule_handle("inet", "nixos-fw", "rpfilter-allow");
        if let Some(h) = handle {
            println!("[+] nft: rpfilter-allow rule added (handle {}).", h);
        }

        Self {
            rpfilter_handle: handle,
        }
    }

    fn revoke(&self) {
        if let Some(handle) = self.rpfilter_handle {
            let _ = std::process::Command::new("nft")
                .args([
                    "delete",
                    "rule",
                    "inet",
                    "nixos-fw",
                    "rpfilter-allow",
                    "handle",
                    &handle.to_string(),
                ])
                .output();
            println!("[+] nft: rpfilter-allow rule revoked.");
        }
    }
}

fn last_rule_handle(family: &str, table: &str, chain: &str) -> Option<u64> {
    let out = std::process::Command::new("nft")
        .args(["-a", "list", "chain", family, table, chain])
        .output()
        .ok()?;

    String::from_utf8_lossy(&out.stdout)
        .lines()
        .rev()
        .find_map(|line| {
            line.rfind("# handle ")
                .and_then(|pos| line[pos + 9..].trim().parse::<u64>().ok())
        })
}

// ─────────────────────────────────────────────────────────────────────────────
// Target expansion (MITM mode only)
// ─────────────────────────────────────────────────────────────────────────────

fn expand_target(s: &str) -> Result<Vec<Ipv4Addr>, String> {
    if s.contains('/') {
        let range =
            network::IpRange::from_cidr(s).map_err(|e| format!("invalid CIDR '{s}': {e}"))?;
        return Ok(range.iter().collect());
    }
    if let Some((prefix, range_part)) = s.rsplit_once('.') {
        if let Some((lo_s, hi_s)) = range_part.split_once('-') {
            let octs = format!("{prefix}.0")
                .parse::<Ipv4Addr>()
                .map_err(|_| format!("invalid prefix '{prefix}'"))?
                .octets();
            let lo: u8 = lo_s
                .parse()
                .map_err(|_| format!("bad range start in '{s}'"))?;
            let hi: u8 = hi_s
                .parse()
                .map_err(|_| format!("bad range end in '{s}'"))?;
            if lo > hi {
                return Err(format!("range start > end in '{s}'"));
            }
            return Ok((lo..=hi)
                .map(|n| Ipv4Addr::new(octs[0], octs[1], octs[2], n))
                .collect());
        }
    }
    s.parse::<Ipv4Addr>()
        .map(|ip| vec![ip])
        .map_err(|_| format!("cannot parse '{s}' as IP, CIDR, or range"))
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut logger = Logger::new();
    check_root();

    let cli = Cli::parse();

    if cli.one_sided {
        println!("[*] One-sided MITM mode: gratuitous ARP takeover");
        // Use new gratuitous ARP approach
    } else {
        println!("[*] Bidirectional MITM mode: traditional poisoning");
        // Use current approach
    }

    // ── Gateway mode early dispatch ──────────────────────────────────────────
    // Must run before the MITM-specific scanner / interface setup below so we
    // don't open raw sockets or manipulate kernel state unnecessarily.
    if cli.gateway_mode {
        if cli.gateway.is_some() {
            eprintln!(
                "[!] --gateway-mode does not use --gateway \
                 (you ARE the gateway — no ARP poisoning)."
            );
            std::process::exit(1);
        }
        let cfg = gateway_mode::GatewayModeConfig {
            interface: cli.interface.clone(),
            bandwidth_kbps: cli.bandwidth,
            // --target is valid in gateway mode: skips the scan and shapes
            // only the specified IPs directly.
            targets: cli.targets.clone(),
        };
        return gateway_mode::run(cfg).await.map_err(Into::into);
    }
    // ── end gateway mode dispatch ────────────────────────────────────────────

    // ── Interface selection ──────────────────────────────────────────────────
    let interface_name = match cli.interface {
        Some(name) => {
            logger.info_fmt(format_args!(
                "Interface (from args): {}",
                COLOR_KEYWORD.paint(&name)
            ));
            name
        }
        None => match InterfaceSelector::select(true) {
            Some(name) => name,
            None => {
                logger.error_fmt(format_args!("No interface selected. Exiting."));
                std::process::exit(1);
            }
        },
    };

    // ── Gateway detection ────────────────────────────────────────────────────
    let gateway_ip = match cli.gateway {
        Some(ip) => {
            logger.info_fmt(format_args!(
                "Gateway (from args): {}",
                COLOR_OK.paint(&ip.to_string())
            ));
            ip
        }
        None => match get_gateway(&interface_name) {
            Some(ip) => {
                logger.info_fmt(format_args!(
                    "Default gateway: {}",
                    COLOR_OK.paint(&ip.to_string())
                ));
                ip
            }
            None => {
                logger.error_fmt(format_args!(
                    "Could not detect default gateway on {}.",
                    interface_name
                ));
                std::process::exit(1);
            }
        },
    };

    // ── Scanner ──────────────────────────────────────────────────────────────
    logger.info_fmt(format_args!(
        "Initialising on interface: {}",
        COLOR_KEYWORD.paint(&interface_name)
    ));
    let scanner = ArpScanner::new(&interface_name).await?;
    logger.info_fmt(format_args!(
        "Local MAC: {}  Local IP: {}",
        COLOR_KEYWORD.paint(&scanner.local_mac().to_string()),
        COLOR_KEYWORD.paint(&scanner.local_ip().to_string()),
    ));

    // ── Host discovery ───────────────────────────────────────────────────────
    let (discovered, bypass_mode) = if !cli.targets.is_empty() {
        let mut ips: Vec<Ipv4Addr> = Vec::new();
        for raw in &cli.targets {
            match expand_target(raw) {
                Ok(v) => {
                    logger.info_fmt(format_args!(
                        "Target '{}' → {} IP(s)",
                        COLOR_KEYWORD.paint(raw),
                        v.len()
                    ));
                    ips.extend(v);
                }
                Err(e) => {
                    logger.error_fmt(format_args!("{e}"));
                    std::process::exit(1);
                }
            }
        }
        ips.sort_unstable();
        ips.dedup();
        if !ips.contains(&gateway_ip) {
            ips.push(gateway_ip);
        }
        logger.info_fmt(format_args!("Bypass mode — resolving {} IP(s)…", ips.len()));
        (scanner.resolve_hosts(&ips).await?, true)
    } else {
        logger.info_fmt(format_args!(
            "Starting ARP scan on: {}",
            COLOR_KEYWORD.paint(&interface_name)
        ));
        let cidr = get_cidr(&interface_name).ok_or("could not determine CIDR")?;
        let range = network::IpRange::from_cidr(&cidr)?;
        logger.info_fmt(format_args!(
            "Scanning {} → {}",
            COLOR_KEYWORD.paint(&range.start.to_string()),
            COLOR_KEYWORD.paint(&range.end.to_string()),
        ));
        logger.info_fmt(format_args!("Passive ARP sniff (10 s)…"));
        let passive = scanner
            .passive_sniff(std::time::Duration::from_secs(10))
            .await?;
        let mut d = scanner.scan(range).await?;
        d.extend(passive);
        logger.info_fmt(format_args!("Post-scan passive sniff (5 s)…"));
        d.extend(
            scanner
                .passive_sniff(std::time::Duration::from_secs(5))
                .await?,
        );
        (d, false)
    };

    // ── Vendor resolution + host table ───────────────────────────────────────
    let mut discovered = discovered;
    logger.info_fmt(format_args!(
        "Resolving vendors for {} hosts…",
        discovered.len()
    ));
    for host in &mut discovered {
        host.vendor = Some(lookup_vendor(host.mac));
    }

    let host_table = Arc::new(RwLock::new(HostTable::new()));
    {
        let mut t = host_table.write().await;
        for host in discovered {
            t.insert(host);
        }
        t.reindex_by_ip();
    }
    {
        host_table.read().await.display();
    }

    // ── Gateway verification ─────────────────────────────────────────────────
    let gateway_mac = {
        let t = host_table.read().await;
        match t.get_by_ip(gateway_ip) {
            Some(e) => e.host.mac,
            None => {
                logger.error_fmt(format_args!("Gateway {} not seen.", gateway_ip));
                std::process::exit(1);
            }
        }
    };
    logger.info_fmt(format_args!(
        "Gateway: {}  MAC: {}",
        COLOR_OK.paint(&gateway_ip.to_string()),
        COLOR_OK.paint(&gateway_mac.to_string()),
    ));

    // ── Target selection ─────────────────────────────────────────────────────

    // Add near the top of main.rs, after imports:

/// Prompts for bandwidth if not provided, returns the user's choice.
fn resolve_bandwidth(
    from_cli: Option<u64>,
    logger: &mut Logger,
) -> Option<u64> {
    match from_cli {
        Some(k) => {
            logger.info_fmt(format_args!("Bandwidth (from args): {} kbps", k));
            Some(k)
        }
        None => {
            use std::io::Write;
            print!(
                "{}",
                crate::paint!(
                    &COLOR_KEYWORD,
                    "Bandwidth cap in kbps per host (leave blank = unlimited): "
                )
            );
            std::io::stdout().flush().unwrap();
            
            let mut buf = String::new();
            match std::io::stdin().read_line(&mut buf) {
                Ok(_) => {
                    let result = TargetSelector::parse_bandwidth(buf.trim());
                    match result {
                        Some(kbps) => logger.info_fmt(format_args!(
                            "Bandwidth limit: {} kbps per host", kbps
                        )),
                        None => logger.info_fmt(format_args!("No bandwidth limit.")),
                    }
                    result
                }
                Err(_) => {
                    logger.error_fmt(format_args!("Failed to read input"));
                    None
                }
            }
        }
    }
}


let selection = if bypass_mode {
    let gw_id = host_table.read().await.get_by_ip(gateway_ip).map(|e| e.id);
    let ids: Vec<_> = host_table.read().await.iter()
        .filter(|e| Some(e.id) != gw_id)
        .map(|e| e.id)
        .collect();
    if ids.is_empty() {
        logger.error_fmt(format_args!("No targets after bypass resolution."));
        std::process::exit(1);
    }
    logger.info_fmt(format_args!("Bypass: {} target(s).", ids.len()));

    let bandwidth_kbps = resolve_bandwidth(cli.bandwidth, &mut logger);

    cli::target_selector::SelectionResult {
        host_ids: ids,
        bandwidth_kbps,
    }
    } else {
        // Interactive path with TargetSelector
        match {
            let t = host_table.read().await;
            TargetSelector::select(&t, gateway_ip) // ← Prompts user
        } {
            Some(s) => s,
            None => {
                logger.info_fmt(format_args!("No targets selected. Exiting."));
                return Ok(());
            }
        }
    };

    // ── Grab what we need from the scanner then drop it ──────────────────────
    let our_mac = scanner.local_mac();
    drop(scanner);

    // ─────────────────────────────────────────────────────────────────────────
    // Infrastructure setup
    // ─────────────────────────────────────────────────────────────────────────

    let kernel_state = match KernelState::enable(&interface_name) {
        Ok(s) => s,
        Err(e) => {
            logger.error_fmt(format_args!("Could not configure kernel state: {e}"));
            std::process::exit(1);
        }
    };
    logger.info_fmt(format_args!(
        "Kernel: ip_forward=0 (userspace forwarder only), rp_filter=0, send_redirects=0."
    ));

    let nft_gate = NftGate::install(&interface_name);

    // ── tc bandwidth shaping ─────────────────────────────────────────────────
    let mut tc = TcManager::new(&interface_name);

    if let Some(kbps) = selection.bandwidth_kbps {
        match tc.init().await {
            Err(e) => {
                logger.error_fmt(format_args!("tc init failed: {e}"));
                nft_gate.revoke();
                kernel_state.restore();
                std::process::exit(1);
            }
            Ok(()) => {
                logger.info_fmt(format_args!(
                    "tc: HTB + IFB shaping initialised on {}.",
                    interface_name
                ));
                let table = host_table.read().await;
                for &id in &selection.host_ids {
                    if let Some(entry) = table.get_by_id(id) {
                        match tc.limit_host(id, entry.host.ip, kbps).await {
                            Ok(()) => logger.info_fmt(format_args!(
                                "tc: [{}] {} → {} kbps",
                                id,
                                COLOR_WARN.paint(&entry.host.ip.to_string()),
                                kbps,
                            )),
                            Err(e) => logger.error_fmt(format_args!(
                                "tc limit_host [{}] {}: {e}",
                                id, entry.host.ip,
                            )),
                        }
                    }
                }
            }
        }
    } else {
        logger.info_fmt(format_args!("No bandwidth cap — forwarding at line rate."));
    }

    // ── Packet forwarder ─────────────────────────────────────────────────────
    let forwarder = match PacketForwarder::new(our_mac, &interface_name, Arc::clone(&host_table)) {
        Ok(f) => f,
        Err(e) => {
            logger.error_fmt(format_args!("Could not create packet forwarder: {e}"));
            tc.cleanup().await;
            nft_gate.revoke();
            kernel_state.restore();
            std::process::exit(1);
        }
    };
    let fwd_tx = forwarder.command_sender();
    tokio::spawn(async move { forwarder.run().await });

    {
        let table = host_table.read().await;
        for &id in &selection.host_ids {
            if let Some(entry) = table.get_by_id(id) {
                let rule = ForwardRule {
                    host_id: id,
                    victim_ip: entry.host.ip,
                    victim_mac: entry.host.mac,
                    gateway_ip,
                    gateway_mac,
                    our_mac,
                };
                if let Err(e) = fwd_tx.send(ForwarderCommand::Enable(rule)).await {
                    logger.error_fmt(format_args!(
                        "Could not enable forwarding for host {id}: {e}"
                    ));
                } else {
                    logger.info_fmt(format_args!(
                        "Forwarding enabled for [{}] {}",
                        id,
                        COLOR_WARN.paint(&entry.host.ip.to_string()),
                    ));
                }
            }
        }
    }

    // ── Spoofer ──────────────────────────────────────────────────────────────
    let spoofer = SpooferEngine::new(our_mac, gateway_ip, &interface_name,Arc::clone(&host_table));

    let spoof_tx = spoofer.command_sender();
    tokio::spawn(async move { spoofer.run().await });

    {
        let table = host_table.read().await;
        for &id in &selection.host_ids {
            if let Some(entry) = table.get_by_id(id) {
                let target =
                    SpoofTarget::new(id, entry.host.ip, entry.host.mac, gateway_ip, gateway_mac);
                if let Err(e) = spoof_tx.send(SpooferCommand::Start(target)).await {
                    logger.error_fmt(format_args!("Could not start poison for host {id}: {e}"));
                } else {
                    logger.info_fmt(format_args!(
                        "Poisoning [{}] {} ({})",
                        id,
                        COLOR_WARN.paint(&entry.host.ip.to_string()),
                        entry.host.mac,
                    ));
                }
            }
        }
    }

    println!();
    logger.info_fmt(format_args!(
        "{}",
        COLOR_OK.paint("Poisoning active. Press Ctrl-C or 'q' + Enter to stop and restore.")
    ));

    // ─────────────────────────────────────────────────────────────────────────
    // Wait for shutdown signal
    // ─────────────────────────────────────────────────────────────────────────
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown_tx = Arc::new(std::sync::Mutex::new(Some(shutdown_tx)));

    {
        let tx = Arc::clone(&shutdown_tx);
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(tokio::signal::ctrl_c()).ok();
            if let Some(sender) = tx.lock().unwrap().take() {
                let _ = sender.send(());
            }
        });
    }

    {
        let tx = Arc::clone(&shutdown_tx);
        std::thread::spawn(move || {
            use std::io::BufRead;
            let stdin = std::io::stdin();
            for line in stdin.lock().lines() {
                match line {
                    Ok(l) if l.trim().eq_ignore_ascii_case("q") => {
                        println!();
                        if let Some(sender) = tx.lock().unwrap().take() {
                            let _ = sender.send(());
                        }
                        break;
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        });
    }

    let _ = shutdown_rx.await;

    // ─────────────────────────────────────────────────────────────────────────
    // Graceful shutdown
    // ─────────────────────────────────────────────────────────────────────────
    println!();
    logger.info_fmt(format_args!("Shutting down…"));

    let _ = fwd_tx.send(ForwarderCommand::DisableAll).await;
    logger.info_fmt(format_args!("Packet forwarding stopped."));

    let _ = spoof_tx.send(SpooferCommand::StopAll).await;
    let restore_wait =
        std::time::Duration::from_millis(600 * (selection.host_ids.len() as u64).max(1));
    tokio::time::sleep(restore_wait).await;
    logger.info_fmt(format_args!("ARP caches restoration sent."));

    tc.cleanup().await;
    logger.info_fmt(format_args!(
        "tc qdiscs, harper_mangle table, and ifb0 removed."
    ));

    kernel_state.restore();
    logger.info_fmt(format_args!("Kernel state restored."));

    nft_gate.revoke();

    logger.info_fmt(format_args!("Done."));
    Ok(())
}
