// src/main.rs
mod cli;
mod forwarder;
mod gateway_mode;
mod host;
mod infra;
mod mitm_auto;
mod network;
mod scanner;
mod spoofer;
mod utils;

#[cfg(test)]
mod bdd;

use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::RwLock;

use clap::Parser;
use pnet::util::MacAddr;

use network::calculator::get_cidr;
use scanner::ArpScanner;

use cli::color::palette;
use cli::selector::InterfaceSelector;
use cli::target_selector::TargetSelector;

use forwarder::engine::PacketForwarder;
use forwarder::{ForwardRule, ForwarderCommand, RelayBackend, RelayHandle};

use host::table::{HostId, HostState, HostTable};

use spoofer::{SpoofTarget, SpooferCommand, SpooferEngine};

use infra::components::{KernelState, NftGate};
use infra::shutdown::ShutdownManager;
use utils::check_root::check_root;
use utils::gateway::get_gateway;
use utils::ip_range::expand_one;
use utils::logger::Logger;
use utils::oui::lookup_vendor;
use utils::shutdown::spawn_shutdown_listener;
use utils::tc::TcManager;

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

    /// Upload bandwidth cap in kbps per host.
    #[arg(long, short = 'u', value_name = "KBPS")]
    upload: Option<u64>,

    /// Download bandwidth cap in kbps per host.
    #[arg(long, short = 'd', value_name = "KBPS")]
    download: Option<u64>,

    /// Bandwidth cap in kbps (applies to both upload and download).
    #[arg(short, long, value_name = "KBPS", conflicts_with_all = &["upload", "download"])]
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

    /// Gateway mode: shape EVERY discovered client automatically.
    /// Skips the interactive target selector.
    #[arg(long, default_value_t = false)]
    all: bool,

    /// Gateway/MITM mode: shared bandwidth pool in kbps.
    #[arg(long, value_name = "KBPS", conflicts_with_all = &["pool_upload", "pool_download"])]
    pool: Option<u64>,

    /// Gateway/MITM mode: shared upload bandwidth pool in kbps.
    #[arg(long, value_name = "KBPS")]
    pool_upload: Option<u64>,

    /// Gateway/MITM mode: shared download bandwidth pool in kbps.
    #[arg(long, value_name = "KBPS")]
    pool_download: Option<u64>,

    /// Gateway/MITM mode: explicitly name the bottleneck uplink device to
    /// EXCLUDE from victims, instead of the auto-detected gateway.
    /// Accepts an IPv4 address or a MAC (e.g. when sitting behind a repeater
    /// whose airtime is the real bottleneck). Falls back to gateway exclusion
    /// if it cannot be resolved to a known host.
    #[arg(long, value_name = "IP|MAC")]
    uplink: Option<String>,

    /// MITM mode: prefer XDP eBPF relay. The fastest backend — operates
    /// on raw DMA frames with no SKB allocation. Requires kernel + NIC
    /// support. Error if unavailable (no fallback to tc).
    #[arg(long, conflicts_with_all = &["kernel", "legacy", "userland", "gateway_mode"])]
    xdp: bool,

    /// MITM mode: use the in-kernel eBPF tc redirect relay (default).
    /// Reduces per-packet copy overhead vs userspace. Falls back to
    /// legacy tc (TC_ACT_OK) if redirect is unavailable.
    #[arg(long, default_value_t = true, conflicts_with_all = &["xdp", "legacy", "userland"])]
    kernel: bool,

    /// MITM mode: force legacy tc eBPF relay (TC_ACT_OK). No devmap
    /// redirect. Useful for debugging or kernels without redirect support.
    #[arg(long, conflicts_with_all = &["xdp", "kernel", "userland", "gateway_mode"])]
    legacy: bool,

    /// MITM mode: use the userspace PacketForwarder instead of the
    /// default in-kernel eBPF relay.
    #[arg(long, conflicts_with_all = &["xdp", "kernel", "legacy", "gateway_mode"])]
    userland: bool,
}

/// Enables relay for a single victim on whichever backend `relay` wraps.
async fn enable_relay(
    logger: &mut Logger,
    relay: &RelayHandle,
    id: HostId,
    vip: Ipv4Addr,
    vmac: MacAddr,
    gmac: MacAddr,
    our_mac: MacAddr,
) {
    match relay {
        RelayHandle::Userspace(tx) => {
            let rule = ForwardRule {
                host_id: id,
                victim_ip: vip,
                victim_mac: vmac,
                gateway_ip: Ipv4Addr::UNSPECIFIED,
                gateway_mac: gmac,
                our_mac,
            };
            if let Err(e) = tx.send(ForwarderCommand::Enable(rule)).await {
                logger.error_fmt(format_args!(
                    "Could not enable forwarding for host {id}: {e}"
                ));
            } else {
                logger.info_fmt(format_args!(
                    "Forwarding enabled for [{}] {}",
                    id,
                    palette::WARN.paint(&vmac.to_string()),
                ));
            }
        }
        RelayHandle::Kernel(r) => {
            r.lock().await.enable(id, vmac, gmac).await;
            logger.info_fmt(format_args!(
                "Forwarding enabled (kernel) for [{}] {}",
                id,
                palette::WARN.paint(&vmac.to_string()),
            ));
        }
    }
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
    // Note: --kernel is now the default; gateway mode ignores it since there's
    // no MITM relay to perform. Gate against explicit --userland if the user
    // tries to combine contradictory relay expectations with gateway mode.
    if cli.userland && cli.gateway_mode {
        eprintln!(
            "[!] --userland (explicit userspace relay) is incompatible with --gateway-mode \
             (gateway mode does no MITM relay)."
        );
        std::process::exit(1);
    }

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
            upload_kbps: cli.upload,
            download_kbps: cli.download,
            bandwidth_kbps: cli.bandwidth,
            // --target is valid in gateway mode: skips the scan and shapes
            // only the specified IPs directly.
            targets: cli.targets.clone(),
            all: cli.all,
            pool_kbps: cli.pool,
            pool_upload_kbps: cli.pool_upload,
            pool_download_kbps: cli.pool_download,
            uplink: cli.uplink.clone(),
        };
        return gateway_mode::run(cfg).await.map_err(Into::into);
    }
    // ── end gateway mode dispatch ────────────────────────────────────────────

    // ── Interface selection ──────────────────────────────────────────────────
    let interface_name = match cli.interface {
        Some(name) => {
            logger.info_fmt(format_args!(
                "Interface (from args): {}",
                palette::KEYWORD.paint(&name)
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
                palette::OK.paint(&ip.to_string())
            ));
            ip
        }
        None => match get_gateway(&interface_name) {
            Some(ip) => {
                logger.info_fmt(format_args!(
                    "Default gateway: {}",
                    palette::OK.paint(&ip.to_string())
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
        palette::KEYWORD.paint(&interface_name)
    ));
    let scanner = ArpScanner::new(&interface_name).await?;
    logger.info_fmt(format_args!(
        "Local MAC: {}  Local IP: {}",
        palette::KEYWORD.paint(&scanner.local_mac().to_string()),
        palette::KEYWORD.paint(&scanner.local_ip().to_string()),
    ));

    // ── Host discovery ───────────────────────────────────────────────────────
    let (discovered, bypass_mode) = if !cli.targets.is_empty() {
        let mut ips: Vec<Ipv4Addr> = Vec::new();
        for raw in &cli.targets {
            match expand_one(raw) {
                Ok(v) => {
                    logger.info_fmt(format_args!(
                        "Target '{}' → {} IP(s)",
                        palette::KEYWORD.paint(raw),
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
            palette::KEYWORD.paint(&interface_name)
        ));
        let cidr = get_cidr(&interface_name).ok_or("could not determine CIDR")?;
        let range = network::IpRange::from_cidr(&cidr)?;
        logger.info_fmt(format_args!(
            "Scanning {} → {}",
            palette::KEYWORD.paint(&range.start.to_string()),
            palette::KEYWORD.paint(&range.end.to_string()),
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
        palette::OK.paint(&gateway_ip.to_string()),
        palette::OK.paint(&gateway_mac.to_string()),
    ));

    // ── Target selection ─────────────────────────────────────────────────────

    fn resolve_bandwidth(
        from_upload: Option<u64>,
        from_download: Option<u64>,
        from_bandwidth: Option<u64>,
        logger: &mut Logger,
    ) -> (Option<u64>, Option<u64>) {
        match (from_upload, from_download, from_bandwidth) {
            (Some(u), Some(d), _) => {
                logger.info_fmt(format_args!("Upload limit: {} kbps, Download limit: {} kbps", u, d));
                (Some(u), Some(d))
            }
            (Some(u), None, _) => {
                logger.info_fmt(format_args!("Upload limit: {} kbps, Download unlimited", u));
                (Some(u), None)
            }
            (None, Some(d), _) => {
                logger.info_fmt(format_args!("Upload unlimited, Download limit: {} kbps", d));
                (None, Some(d))
            }
            (None, None, Some(b)) => {
                logger.info_fmt(format_args!("Bandwidth (from args): {} kbps per host", b));
                (Some(b), Some(b))
            }
            (None, None, None) => {
                use std::io::Write;
                print!(
                    "{}",
                    crate::paint!(
                        &palette::KEYWORD,
                        "Bandwidth cap in kbps per host [upload/download or single value] (leave blank = unlimited): "
                    )
                );
                std::io::stdout().flush().unwrap();

                let mut buf = String::new();
                match std::io::stdin().read_line(&mut buf) {
                    Ok(_) => {
                        let (up, down) = TargetSelector::parse_bandwidth(buf.trim());
                        match (up, down) {
                            (Some(u), Some(d)) if u == d => logger
                                .info_fmt(format_args!("Bandwidth limit: {} kbps per host", u)),
                            (Some(u), Some(d)) => logger
                                .info_fmt(format_args!("Bandwidth limit: upload {} kbps, download {} kbps", u, d)),
                            (Some(u), None) => logger
                                .info_fmt(format_args!("Bandwidth limit: upload {} kbps, download unlimited", u)),
                            (None, Some(d)) => logger
                                .info_fmt(format_args!("Bandwidth limit: upload unlimited, download {} kbps", d)),
                            (None, None) => logger.info_fmt(format_args!("No bandwidth limit.")),
                        }
                        (up, down)
                    }
                    Err(_) => {
                        logger.error_fmt(format_args!("Failed to read input"));
                        (None, None)
                    }
                }
            }
        }
    }

    /// Resolves `--uplink <ip|mac>` to the IP of the device to exclude from
    /// victims in MITM mode. Falls back to `gateway_ip` when absent or unresolved.
    fn resolve_uplink(
        table: &HostTable,
        uplink: &Option<String>,
        gateway_ip: Ipv4Addr,
    ) -> Ipv4Addr {
        let Some(hint) = uplink else {
            return gateway_ip;
        };
        if let Ok(ip) = hint.parse::<Ipv4Addr>() {
            if table.get_by_ip(ip).is_some() {
                return ip;
            }
            return gateway_ip;
        }
        if let Some(mac) = parse_mac(hint) {
            if let Some(entry) = table.get_by_mac(mac) {
                return entry.host.ip;
            }
        }
        gateway_ip
    }

    /// Parses a colon-separated MAC ("00:11:22:33:44:55") into `MacAddr`.
    fn parse_mac(s: &str) -> Option<MacAddr> {
        let mut octets = [0u8; 6];
        let mut i = 0;
        for part in s.split(':') {
            if i >= 6 {
                return None;
            }
            octets[i] = u8::from_str_radix(part, 16).ok()?;
            i += 1;
        }
        if i != 6 {
            return None;
        }
        Some(MacAddr::new(
            octets[0], octets[1], octets[2], octets[3], octets[4], octets[5],
        ))
    }

    let excluded_ip = {
        let t = host_table.read().await;
        resolve_uplink(&t, &cli.uplink, gateway_ip)
    };
    if cli.uplink.is_some() && excluded_ip == gateway_ip {
        logger.error_fmt(format_args!(
            "Could not resolve --uplink {:?} to a known host; falling back to gateway exclusion.",
            cli.uplink.as_deref().unwrap()
        ));
    } else if cli.uplink.is_some() {
        logger.info_fmt(format_args!(
            "Excluding uplink {} from victims.",
            excluded_ip
        ));
    }

    let has_pool = cli.pool.is_some() || cli.pool_upload.is_some() || cli.pool_download.is_some();
    let selection = if bypass_mode {
        let ids: Vec<_> = host_table
            .read()
            .await
            .iter()
            .filter(|e| e.host.ip != excluded_ip)
            .map(|e| e.id)
            .collect();
        if ids.is_empty() {
            logger.error_fmt(format_args!("No targets after bypass resolution."));
            std::process::exit(1);
        }
        logger.info_fmt(format_args!("Bypass: {} target(s).", ids.len()));

        let (up, down) = if has_pool {
            (None, None)
        } else {
            resolve_bandwidth(cli.upload, cli.download, cli.bandwidth, &mut logger)
        };

        cli::target_selector::SelectionResult {
            host_ids: ids,
            upload_kbps: up,
            download_kbps: down,
        }
    } else if cli.all {
        // `--all` in MITM mode: auto-select every discovered host except the
        // uplink/gateway, then keep dynamically adding new arrivals at runtime.
        let ids: Vec<_> = host_table
            .read()
            .await
            .iter()
            .filter(|e| e.host.ip != excluded_ip)
            .map(|e| e.id)
            .collect();
        if ids.is_empty() {
            logger.error_fmt(format_args!("No targets after discovery."));
            std::process::exit(1);
        }
        logger.info_fmt(format_args!(
            "Auto-select (--all): {} target(s).",
            ids.len()
        ));

        let (up, down) = if has_pool {
            (None, None)
        } else {
            resolve_bandwidth(cli.upload, cli.download, cli.bandwidth, &mut logger)
        };

        cli::target_selector::SelectionResult {
            host_ids: ids,
            upload_kbps: up,
            download_kbps: down,
        }
    } else {
        // Interactive path with TargetSelector
        match {
            let t = host_table.read().await;
            TargetSelector::select_with(&t, excluded_ip, has_pool) // ← Prompts user; excludes uplink/gateway; skips bandwidth prompt if pool given
        } {
            Some(mut s) => {
                if let Some(b) = cli.bandwidth {
                    s.upload_kbps = Some(b);
                    s.download_kbps = Some(b);
                    logger.info_fmt(format_args!("Bandwidth (from args): {} kbps", b));
                }
                if let Some(u) = cli.upload {
                    s.upload_kbps = Some(u);
                    logger.info_fmt(format_args!("Upload bandwidth (from args): {} kbps", u));
                }
                if let Some(d) = cli.download {
                    s.download_kbps = Some(d);
                    logger.info_fmt(format_args!("Download bandwidth (from args): {} kbps", d));
                }
                s
            }
            None => {
                logger.info_fmt(format_args!("No targets selected. Exiting."));
                return Ok(());
            }
        }
    };

    // ── Grab what we need from the scanner then drop it ──────────────────────
    let our_mac = scanner.local_mac();
    let our_ip = scanner.local_ip();
    drop(scanner);

    // ─────────────────────────────────────────────────────────────────────────
    // Infrastructure setup
    // ─────────────────────────────────────────────────────────────────────────

    let mut shutdown_manager = ShutdownManager::new();

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
    shutdown_manager.add(Box::new(kernel_state));

    let nft_gate = NftGate::install(&interface_name);
    shutdown_manager.add(Box::new(nft_gate));

    // ── tc bandwidth shaping ─────────────────────────────────────────────────
    // Wrapped in Option so ownership can be handed to the dynamic MITM manager
    // (--all) at setup time; in other modes it stays here for teardown.
    let mut tc = Some(TcManager::new(&interface_name));

    // Pool mode: all selected victims share ONE HTB class of `pool_kbps`.
    // Unshaped traffic (the attacker) keeps the rest of the line rate via the
    // passthrough default class. Mutually exclusive with per-host --bandwidth;
    // pool wins when both are given (mirrors gateway-mode behaviour).
    let pool_upload = cli.pool_upload.or(cli.pool);
    let pool_download = cli.pool_download.or(cli.pool);

    if pool_upload.is_some() || pool_download.is_some() {
        if pool_upload.map_or(false, |k| k == 0) || pool_download.map_or(false, |k| k == 0) {
            logger.error_fmt(format_args!(
                "--pool must be a positive kbps value (got 0)."
            ));
            shutdown_manager.shutdown().await;
            std::process::exit(1);
        }
        match tc.as_mut().unwrap().init().await {
            Err(e) => {
                logger.error_fmt(format_args!("tc init failed: {e}"));
                shutdown_manager.shutdown().await;
                std::process::exit(1);
            }
            Ok(()) => {
                logger.info_fmt(format_args!(
                    "tc: HTB + IFB shaping initialised on {}.",
                    interface_name
                ));

                let table = host_table.read().await;
                let victim_ips: Vec<Ipv4Addr> = selection
                    .host_ids
                    .iter()
                    .filter_map(|&id| table.get_by_id(id).map(|e| e.host.ip))
                    .collect();
                if victim_ips.is_empty() {
                    logger.error_fmt(format_args!("No victims to pool."));
                    shutdown_manager.shutdown().await;
                    std::process::exit(1);
                }
                match tc
                    .as_mut()
                    .unwrap()
                    .limit_pool_split(pool_upload, pool_download, &victim_ips)
                    .await
                {
                    Ok(()) => logger.info_fmt(format_args!(
                        "tc: {} client(s) share a pool (upload: {:?}, download: {:?}); attacker keeps the rest.",
                        victim_ips.len(),
                        pool_upload,
                        pool_download
                    )),
                    Err(e) => logger.error_fmt(format_args!("tc limit_pool_split failed: {e}")),
                }
            }
        }
    } else if selection.upload_kbps.is_some() || selection.download_kbps.is_some() {
        match tc.as_mut().unwrap().init().await {
            Err(e) => {
                logger.error_fmt(format_args!("tc init failed: {e}"));
                shutdown_manager.shutdown().await;
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
                        match tc
                            .as_mut()
                            .unwrap()
                            .limit_host(id, entry.host.ip, selection.upload_kbps, selection.download_kbps)
                            .await
                        {
                            Ok(()) => logger.info_fmt(format_args!(
                                "tc: [{}] {} → upload: {:?}, download: {:?}",
                                id,
                                palette::WARN.paint(&entry.host.ip.to_string()),
                                selection.upload_kbps,
                                selection.download_kbps,
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
    // Three kernel relay backends plus userspace fallback:
    //   --xdp       → XDP (error if unsupported)
    //   --kernel    → tc redirect (default), falls back to tc legacy
    //   --legacy    → tc legacy (TC_ACT_OK)
    //   --userland  → userspace PacketForwarder
    let relay_preference = if cli.xdp {
        RelayBackend::Xdp
    } else if cli.legacy {
        RelayBackend::TcLegacy
    } else {
        RelayBackend::TcRedirect // default
    };

    let relay: RelayHandle = if cli.userland {
        let forwarder =
            match PacketForwarder::new(our_mac, &interface_name, Arc::clone(&host_table)) {
                Ok(f) => f,
                Err(e) => {
                    logger.error_fmt(format_args!("Could not create packet forwarder: {e}"));
                    tc.as_mut().unwrap().cleanup().await;
                    shutdown_manager.shutdown().await;
                    std::process::exit(1);
                }
            };
        let fwd_tx = forwarder.command_sender();
        tokio::spawn(async move { forwarder.run().await });
        RelayHandle::Userspace(fwd_tx)
    } else {
        match crate::forwarder::ebpf::KernelRelay::attach_best_available(
            &interface_name,
            our_mac,
            relay_preference,
        ) {
            Ok(r) => {
                let label = match r.backend {
                    RelayBackend::Xdp => "XDP",
                    RelayBackend::TcRedirect => "tc redirect",
                    RelayBackend::TcLegacy => "tc legacy",
                };
                println!("[*] Kernel eBPF relay active ({label}).");
                RelayHandle::Kernel(Arc::new(tokio::sync::Mutex::new(r)))
            }
            Err(e) => {
                logger.error_fmt(format_args!(
                    "Could not attach kernel relay: {e}. Falling back to userspace forwarder."
                ));
                let forwarder =
                    match PacketForwarder::new(our_mac, &interface_name, Arc::clone(&host_table)) {
                        Ok(f) => f,
                        Err(e2) => {
                            logger
                                .error_fmt(format_args!("Could not create packet forwarder: {e2}"));
                            tc.as_mut().unwrap().cleanup().await;
                            shutdown_manager.shutdown().await;
                            std::process::exit(1);
                        }
                    };
                let fwd_tx = forwarder.command_sender();
                tokio::spawn(async move { forwarder.run().await });
                RelayHandle::Userspace(fwd_tx)
            }
        }
    };

    {
        let table = host_table.read().await;
        for &id in &selection.host_ids {
            if let Some(entry) = table.get_by_id(id) {
                enable_relay(
                    &mut logger,
                    &relay,
                    id,
                    entry.host.ip,
                    entry.host.mac,
                    gateway_mac,
                    our_mac,
                )
                .await;
            }
        }
    }

    // ── Spoofer ──────────────────────────────────────────────────────────────
    let spoofer = SpooferEngine::new(
        our_mac,
        our_ip,
        gateway_ip,
        &interface_name,
        Arc::clone(&host_table),
        cli.one_sided,
    );

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
                        palette::WARN.paint(&entry.host.ip.to_string()),
                        entry.host.mac,
                    ));
                }
            }
        }
    }

    // ── Dynamic MITM manager (--all) ──────────────────────────────────────────
    // When --all is given, Harper keeps watching the wire and auto-adds future
    // devices to the MITM. The manager takes ownership of `tc` (so it can shape
    // new victims and tear tc down on exit); in non- --all mode `tc` stays with
    // the shutdown manager as before.
    let (auto_stop_tx, auto_task) = if cli.all {
        let spoof_tx_clone = spoof_tx.clone();
        let relay_clone = Arc::new(relay.clone());

        let mut manager = mitm_auto::MitmAutoManager::new(
            interface_name.clone(),
            our_mac,
            our_ip,
            gateway_ip,
            gateway_mac,
            excluded_ip,
            Arc::clone(&host_table),
            spoof_tx_clone,
            relay_clone,
            tc.take().unwrap(),
            pool_upload,
            pool_download,
            selection.upload_kbps,
            selection.download_kbps,
        );
        manager.seed(&selection.host_ids).await;

        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(async move { manager.run(stop_rx).await });
        logger.info_fmt(format_args!(
            "Dynamic MITM (--all) active: new devices will be auto-added; stale ones evicted."
        ));
        (Some(stop_tx), Some(task))
    } else {
        (None, None)
    };

    println!();
    logger.info_fmt(format_args!(
        "{}",
        palette::OK.paint("Poisoning active. Press Ctrl-C or 'q' + Enter to stop and restore.")
    ));

    // ─────────────────────────────────────────────────────────────────────────
    // Wait for shutdown signal
    // ─────────────────────────────────────────────────────────────────────────
    let shutdown_rx = spawn_shutdown_listener();

    let _ = shutdown_rx.await;

    // ─────────────────────────────────────────────────────────────────────────
    // Graceful shutdown
    // ─────────────────────────────────────────────────────────────────────────
    println!();
    logger.info_fmt(format_args!("Shutting down…"));

    relay.disable_all().await;
    logger.info_fmt(format_args!("Packet forwarding stopped."));

    let _ = spoof_tx.send(SpooferCommand::StopAll).await;
    let restore_wait =
        std::time::Duration::from_millis(600 * (selection.host_ids.len() as u64).max(1));
    tokio::time::sleep(restore_wait).await;
    logger.info_fmt(format_args!("ARP caches restoration sent."));

    if let (Some(stop_tx), Some(task)) = (auto_stop_tx, auto_task) {
        // Signal the dynamic manager; it evicts all victims and runs tc.cleanup().
        let _ = stop_tx.send(());
        let _ = task.await;
    } else {
        shutdown_manager.add(Box::new(tc.take().unwrap()));
        shutdown_manager.shutdown().await;
    }

    logger.info_fmt(format_args!("Done."));
    Ok(())
}
