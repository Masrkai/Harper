// src/gateway_mode.rs
//
// Gateway mode — bandwidth shaping for clients on a network you host.
// No ARP poisoning. The kernel already routes traffic through this machine.
// Only tc HTB shaping is applied on the interface that serves the clients.

use std::net::Ipv4Addr;
use std::sync::Arc;

use pnet::util::MacAddr;

use tokio::sync::RwLock;

use crate::cli::color::palette;
use crate::cli::selector::InterfaceSelector;
use crate::cli::target_selector::{SelectionResult, TargetSelector};
use crate::host::table::HostTable;
use crate::network::IpRange;
use crate::network::calculator::get_cidr;
use crate::scanner::ArpScanner;
use crate::utils::ip_range::expand_targets;
use crate::utils::logger::Logger;
use crate::utils::oui::lookup_vendor;
use crate::utils::shutdown::spawn_shutdown_listener;
use crate::utils::tc::TcManager;

// ─────────────────────────────────────────────────────────────────────────────

pub struct GatewayModeConfig {
    pub interface: Option<String>,
    pub upload_kbps: Option<u64>,
    pub download_kbps: Option<u64>,
    pub bandwidth_kbps: Option<u64>,
    pub targets: Vec<String>,
    pub all: bool,
    pub pool_kbps: Option<u64>,
    pub pool_upload_kbps: Option<u64>,
    pub pool_download_kbps: Option<u64>,
    pub uplink: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────

pub async fn run(cfg: GatewayModeConfig) -> Result<(), Box<dyn std::error::Error>> {
    let mut logger = Logger::new();

    logger.info_fmt(format_args!(
        "{}",
        palette::OK.paint("Gateway mode — shaping clients on a network you host")
    ));
    logger.info_fmt(format_args!(
        "No ARP poisoning. Kernel routing handles forwarding."
    ));

    // ── Interface selection ──────────────────────────────────────────────────
    let interface_name = match cfg.interface {
        Some(ref name) => {
            logger.info_fmt(format_args!(
                "Interface (from args): {}",
                palette::KEYWORD.paint(name)
            ));
            name.clone()
        }
        None => match InterfaceSelector::select(true) {
            Some(name) => name,
            None => {
                logger.error_fmt(format_args!("No interface selected. Exiting."));
                std::process::exit(1);
            }
        },
    };

    // ── Scanner (for local MAC/IP + active-scan fallback) ────────────────────
    let scanner = ArpScanner::new(&interface_name).await?;
    let our_ip = scanner.local_ip();
    logger.info_fmt(format_args!(
        "Local MAC: {}  Local IP: {}",
        palette::KEYWORD.paint(&scanner.local_mac().to_string()),
        palette::KEYWORD.paint(&our_ip.to_string()),
    ));

    // ── Host discovery ───────────────────────────────────────────────────────
    let (discovered, bypass_mode) = if !cfg.targets.is_empty() {
        let ips = match expand_targets(&cfg.targets) {
            Ok(v) => v,
            Err(e) => {
                logger.error_fmt(format_args!("{e}"));
                std::process::exit(1);
            }
        };
        logger.info_fmt(format_args!("Bypass mode — resolving {} IP(s)…", ips.len()));
        (scanner.resolve_hosts(&ips).await?, true)
    } else {
        // Cache-first: the kernel already knows every client it forwards for.
        // An active scan is only a fallback for when the neighbour cache is
        // empty (e.g. no client has sent a packet yet).
        let cached = crate::utils::neighbors::discover_via_cache(&interface_name, our_ip);

        if !cached.is_empty() {
            logger.info_fmt(format_args!(
                "Discovered {} client(s) from kernel ARP cache.",
                cached.len()
            ));
            (cached, false)
        } else {
            let cidr = get_cidr(&interface_name).ok_or("could not determine CIDR for interface")?;
            let range = IpRange::from_cidr(&cidr)?;
            logger.info_fmt(format_args!(
                "ARP cache empty — scanning {} → {}",
                palette::KEYWORD.paint(&range.start.to_string()),
                palette::KEYWORD.paint(&range.end.to_string()),
            ));

            logger.info_fmt(format_args!("Passive ARP sniff (5 s)…"));
            let passive = scanner
                .passive_sniff(std::time::Duration::from_secs(5))
                .await?;

            let mut d = scanner.scan(range).await?;
            d.extend(passive);

            logger.info_fmt(format_args!("Post-scan passive sniff (3 s)…"));
            d.extend(
                scanner
                    .passive_sniff(std::time::Duration::from_secs(3))
                    .await?,
            );
            (d, false)
        }
    };

    // ── Vendor resolution ────────────────────────────────────────────────────
    let mut discovered = discovered;
    for host in &mut discovered {
        host.vendor = Some(lookup_vendor(host.mac));
    }

    // ── Build host table ─────────────────────────────────────────────────────
    drop(scanner);

    let host_table = Arc::new(RwLock::new(HostTable::new()));
    {
        let mut t = host_table.write().await;
        for host in discovered {
            if host.ip == our_ip {
                continue;
            }
            t.insert(host);
        }
        t.reindex_by_ip();
    }
    host_table.read().await.display();

    if host_table.read().await.is_empty() {
        logger.error_fmt(format_args!("No clients found on {}.", interface_name));
        return Ok(());
    }

    // ── Resolve uplink exclusion ──────────────────────────────────────────────
    // `--uplink` names the bottleneck device to keep OUT of the victim pool
    // (e.g. a repeater whose airtime is the real constraint). Falls back to
    // excluding ourselves when it can't be resolved.
    let excluded_ip = {
        let t = host_table.read().await;
        resolve_uplink(&t, &cfg.uplink, our_ip)
    };
    if cfg.uplink.is_some() {
        if excluded_ip == our_ip {
            logger.error_fmt(format_args!(
                "Could not resolve --uplink {:?} to a known host; falling back to excluding self.",
                cfg.uplink.as_deref().unwrap()
            ));
        } else {
            logger.info_fmt(format_args!(
                "Excluding uplink {} from victims.",
                excluded_ip
            ));
        }
    }

    // ── Target + bandwidth selection ─────────────────────────────────────────
    // All stdin interaction must finish here, BEFORE spawn_shutdown_listener().
    let selection: SelectionResult = if bypass_mode {
        let ids: Vec<_> = host_table
            .read()
            .await
            .iter()
            .filter(|e| e.host.ip != excluded_ip)
            .map(|e| e.id)
            .collect();
        if ids.is_empty() {
            logger.error_fmt(format_args!("No targets after resolution."));
            return Ok(());
        }
        logger.info_fmt(format_args!("Bypass: {} target(s) selected.", ids.len()));

        let (upload_limit, download_limit) = match (cfg.upload_kbps, cfg.download_kbps, cfg.bandwidth_kbps) {
            (Some(u), Some(d), _) => (Some(u), Some(d)),
            (Some(u), None, _) => (Some(u), None),
            (None, Some(d), _) => (None, Some(d)),
            (None, None, Some(b)) => (Some(b), Some(b)),
            (None, None, None) => prompt_bandwidth_once(),
        };

        SelectionResult {
            host_ids: ids,
            upload_kbps: upload_limit,
            download_kbps: download_limit,
        }
    } else if cfg.all {
        let ids: Vec<_> = host_table
            .read()
            .await
            .iter()
            .filter(|e| e.host.ip != excluded_ip)
            .map(|e| e.id)
            .collect();
        if ids.is_empty() {
            logger.error_fmt(format_args!("No clients to shape."));
            return Ok(());
        }
        logger.info_fmt(format_args!(
            "Auto-select (--all): {} target(s).",
            ids.len()
        ));

        let (upload_limit, download_limit) = match (cfg.upload_kbps, cfg.download_kbps, cfg.bandwidth_kbps) {
            (Some(u), Some(d), _) => (Some(u), Some(d)),
            (Some(u), None, _) => (Some(u), None),
            (None, Some(d), _) => (None, Some(d)),
            (None, None, Some(b)) => (Some(b), Some(b)),
            (None, None, None) => prompt_bandwidth_once(),
        };

        SelectionResult {
            host_ids: ids,
            upload_kbps: upload_limit,
            download_kbps: download_limit,
        }
    } else {
        let t = host_table.read().await;
        match TargetSelector::select(&t, excluded_ip) {
            Some(mut s) => {
                if let Some(k) = cfg.bandwidth_kbps {
                    s.upload_kbps = Some(k);
                    s.download_kbps = Some(k);
                    logger.info_fmt(format_args!("Bandwidth (from args): {} kbps", k));
                }
                if let Some(u) = cfg.upload_kbps {
                    s.upload_kbps = Some(u);
                    logger.info_fmt(format_args!("Upload bandwidth (from args): {} kbps", u));
                }
                if let Some(d) = cfg.download_kbps {
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

    let pool_upload = cfg.pool_upload_kbps.or(cfg.pool_kbps);
    let pool_download = cfg.pool_download_kbps.or(cfg.pool_kbps);
    let upload_limit = cfg.upload_kbps.or(cfg.bandwidth_kbps).or(selection.upload_kbps);
    let download_limit = cfg.download_kbps.or(cfg.bandwidth_kbps).or(selection.download_kbps);

    // ── tc initialisation ────────────────────────────────────────────────────
    let mut tc = TcManager::new(&interface_name);

    match tc.init().await {
        Err(e) => {
            logger.error_fmt(format_args!("tc init failed: {e}"));
            std::process::exit(1);
        }
        Ok(()) => logger.info_fmt(format_args!(
            "tc: HTB + IFB shaping initialised on {}.",
            interface_name
        )),
    }

    // Pool mode: all selected victims share ONE HTB class of `pool_kbps`.
    // Unshaped traffic (the attacker) keeps the rest of the line rate via the
    // passthrough default class. Mutually exclusive with per-host --bandwidth.
    if pool_upload.is_some() || pool_download.is_some() {
        let table = host_table.read().await;
        let victim_ips: Vec<Ipv4Addr> = selection
            .host_ids
            .iter()
            .filter_map(|&id| table.get_by_id(id).map(|e| e.host.ip))
            .collect();
        if victim_ips.is_empty() {
            logger.error_fmt(format_args!("No victims to pool."));
            return Ok(());
        }
        match tc.limit_pool_split(pool_upload, pool_download, &victim_ips).await {
            Ok(()) => logger.info_fmt(format_args!(
                "tc: {} client(s) share a pool (upload: {:?}, download: {:?}).",
                victim_ips.len(),
                pool_upload,
                pool_download
            )),
            Err(e) => logger.error_fmt(format_args!("tc limit_pool_split failed: {e}")),
        }
    } else if upload_limit.is_some() || download_limit.is_some() {
        let table = host_table.read().await;
        for &id in &selection.host_ids {
            if let Some(entry) = table.get_by_id(id) {
                match tc.limit_host(id, entry.host.ip, upload_limit, download_limit).await {
                    Ok(()) => logger.info_fmt(format_args!(
                        "tc: [{}] {} → upload: {:?}, download: {:?}",
                        id,
                        palette::WARN.paint(&entry.host.ip.to_string()),
                        upload_limit,
                        download_limit,
                    )),
                    Err(e) => logger.error_fmt(format_args!(
                        "tc limit_host [{}] {}: {e}",
                        id, entry.host.ip,
                    )),
                }
            }
        }
    } else {
        logger.info_fmt(format_args!(
            "No bandwidth cap — {} client(s) forwarded at line rate.",
            selection.host_ids.len()
        ));
    }

    // ── Status + shutdown ────────────────────────────────────────────────────
    let has_limit = upload_limit.is_some() || download_limit.is_some() || pool_upload.is_some() || pool_download.is_some();
    let status_msg = if has_limit {
        format!(
            "Shaping {} client(s). Press Ctrl-C or 'q' + Enter to stop.",
            selection.host_ids.len(),
        )
    } else {
        format!(
            "Monitoring {} client(s) (no cap). Press Ctrl-C or 'q' + Enter to stop.",
            selection.host_ids.len(),
        )
    };
    logger.info_fmt(format_args!("{}", palette::OK.paint(&status_msg)));

    // Spawned HERE — after ALL stdin interaction is complete.
    let shutdown_rx = spawn_shutdown_listener();
    let _ = shutdown_rx.await;

    // ── Teardown ──────────────────────────────────────────────────────────────
    println!();
    logger.info_fmt(format_args!("Shutting down gateway mode…"));
    tc.cleanup().await;
    logger.info_fmt(format_args!("tc qdiscs removed. Network restored."));
    logger.info_fmt(format_args!("Done."));

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────

fn prompt_bandwidth_once() -> (Option<u64>, Option<u64>) {
    use std::io::Write as _;
    print!("Bandwidth cap in kbps per client [upload/download or single value] (leave blank = unlimited): ");
    std::io::stdout().flush().unwrap();
    let mut buf = String::new();
    if std::io::stdin().read_line(&mut buf).is_ok() {
        return TargetSelector::parse_bandwidth(buf.trim());
    }
    (None, None)
}

/// Resolves `--uplink <ip|mac>` to the IP of the device to exclude from
/// shaping. Falls back to `our_ip` when the hint is absent or cannot be
/// resolved to a known host (so behaviour degrades to excluding ourselves,
/// i.e. shaping everyone else).
pub(crate) fn resolve_uplink(
    table: &HostTable,
    uplink: &Option<String>,
    our_ip: Ipv4Addr,
) -> Ipv4Addr {
    let Some(hint) = uplink else {
        return our_ip;
    };

    // Try IPv4 first.
    if let Ok(ip) = hint.parse::<Ipv4Addr>() {
        if table.get_by_ip(ip).is_some() {
            return ip;
        }
        // Unknown IP — fall back to self exclusion rather than shaping blindly.
        return our_ip;
    }

    // Try MAC (colon-separated).
    if let Some(mac) = parse_mac(hint) {
        if let Some(entry) = table.get_by_mac(mac) {
            return entry.host.ip;
        }
    }

    our_ip
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

// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_fields() {
        let cfg = GatewayModeConfig {
            interface: Some("eth0".to_string()),
            upload_kbps: None,
            download_kbps: None,
            bandwidth_kbps: Some(1024),
            targets: vec!["10.0.0.1".to_string()],
            all: false,
            pool_kbps: None,
            pool_upload_kbps: None,
            pool_download_kbps: None,
            uplink: None,
        };
        assert_eq!(cfg.interface.as_deref(), Some("eth0"));
        assert_eq!(cfg.bandwidth_kbps, Some(1024));
        assert_eq!(cfg.targets.len(), 1);

        // Empty targets → full scan path
        let empty = GatewayModeConfig {
            interface: None,
            upload_kbps: None,
            download_kbps: None,
            bandwidth_kbps: None,
            targets: vec![],
            all: false,
            pool_kbps: None,
            pool_upload_kbps: None,
            pool_download_kbps: None,
            uplink: None,
        };
        assert!(empty.targets.is_empty());
    }

    // expand_targets / expand_one tests live in utils/ip_range.rs;
    // here we only verify the gateway_mode-specific wrapper behavior.
    #[test]
    fn test_expand_targets_used_in_gateway_mode() {
        use crate::utils::ip_range::expand_targets;

        let ips = expand_targets(&["10.0.0.1-3".to_string()]).unwrap();
        assert_eq!(ips.len(), 3);
        assert_eq!(ips[0], "10.0.0.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(ips[2], "10.0.0.3".parse::<Ipv4Addr>().unwrap());

        assert!(expand_targets(&["not_an_ip".to_string()]).is_err());
    }

    #[test]
    fn test_resolve_uplink_ip_mac_and_fallback() {
        use crate::host::table::DiscoveredHost;
        use pnet::util::MacAddr;
        use std::time::Instant;

        let mut table = HostTable::new();
        table.insert(DiscoveredHost {
            ip: Ipv4Addr::new(10, 0, 0, 1),
            mac: MacAddr::new(0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01),
            hostname: None,
            vendor: None,
            last_seen: Instant::now(),
        });
        // Re-index so IP/MAC lookups are populated.
        table.reindex_by_ip();

        let our_ip = Ipv4Addr::new(192, 168, 1, 100);

        // No hint → exclude self.
        assert_eq!(resolve_uplink(&table, &None, our_ip), our_ip);

        // Resolve by IP.
        assert_eq!(
            resolve_uplink(&table, &Some("10.0.0.1".to_string()), our_ip),
            Ipv4Addr::new(10, 0, 0, 1)
        );

        // Resolve by MAC.
        assert_eq!(
            resolve_uplink(&table, &Some("AA:BB:CC:00:00:01".to_string()), our_ip),
            Ipv4Addr::new(10, 0, 0, 1)
        );

        // Unresolvable hint → fall back to self exclusion.
        assert_eq!(
            resolve_uplink(&table, &Some("10.9.9.9".to_string()), our_ip),
            our_ip
        );
        assert_eq!(
            resolve_uplink(&table, &Some("ZZ:ZZ:ZZ:ZZ:ZZ:ZZ".to_string()), our_ip),
            our_ip
        );
    }
}
