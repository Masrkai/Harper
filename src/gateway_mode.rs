// src/gateway_mode.rs
//
// Gateway mode — bandwidth shaping for clients on a network you host.
// No ARP poisoning. The kernel already routes traffic through this machine.
// Only tc HTB shaping is applied on the interface that serves the clients.

use std::net::Ipv4Addr;
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::cli::color::Color;
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

const COLOR_OK:      Color = Color::from_hex(b"#50C878");
const COLOR_WARN:    Color = Color::from_hex(b"#FFB347");
const COLOR_KEYWORD: Color = Color::from_hex(b"#C792EA");

// ─────────────────────────────────────────────────────────────────────────────

pub struct GatewayModeConfig {
    pub interface:      Option<String>,
    pub bandwidth_kbps: Option<u64>,
    pub targets:        Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────────

pub async fn run(cfg: GatewayModeConfig) -> Result<(), Box<dyn std::error::Error>> {
    let mut logger = Logger::new();

    logger.info_fmt(format_args!(
        "{}", COLOR_OK.paint("Gateway mode — shaping clients on a network you host")
    ));
    logger.info_fmt(format_args!("No ARP poisoning. Kernel routing handles forwarding."));

    // ── Interface selection ──────────────────────────────────────────────────
    let interface_name = match cfg.interface {
        Some(ref name) => {
            logger.info_fmt(format_args!("Interface (from args): {}", COLOR_KEYWORD.paint(name)));
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

    // ── Scanner ──────────────────────────────────────────────────────────────
    let scanner = ArpScanner::new(&interface_name).await?;
    let our_ip = scanner.local_ip();
    logger.info_fmt(format_args!(
        "Local MAC: {}  Local IP: {}",
        COLOR_KEYWORD.paint(&scanner.local_mac().to_string()),
        COLOR_KEYWORD.paint(&our_ip.to_string()),
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
        let cidr = get_cidr(&interface_name).ok_or("could not determine CIDR for interface")?;
        let range = IpRange::from_cidr(&cidr)?;
        logger.info_fmt(format_args!(
            "Scanning {} → {}",
            COLOR_KEYWORD.paint(&range.start.to_string()),
            COLOR_KEYWORD.paint(&range.end.to_string()),
        ));

        logger.info_fmt(format_args!("Passive ARP sniff (5 s)…"));
        let passive = scanner.passive_sniff(std::time::Duration::from_secs(5)).await?;

        let mut d = scanner.scan(range).await?;
        d.extend(passive);

        logger.info_fmt(format_args!("Post-scan passive sniff (3 s)…"));
        d.extend(scanner.passive_sniff(std::time::Duration::from_secs(3)).await?);
        (d, false)
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
            if host.ip == our_ip { continue; }
            t.insert(host);
        }
        t.reindex_by_ip();
    }
    host_table.read().await.display();

    if host_table.read().await.is_empty() {
        logger.error_fmt(format_args!("No clients found on {}.", interface_name));
        return Ok(());
    }

    // ── Target + bandwidth selection ─────────────────────────────────────────
    // All stdin interaction must finish here, BEFORE spawn_shutdown_listener().
    let selection: SelectionResult = if bypass_mode {
        let ids: Vec<_> = host_table.read().await.iter().map(|e| e.id).collect();
        if ids.is_empty() {
            logger.error_fmt(format_args!("No targets after resolution."));
            return Ok(());
        }
        logger.info_fmt(format_args!("Bypass: {} target(s) selected.", ids.len()));

        let kbps = match cfg.bandwidth_kbps {
            Some(k) => {
                logger.info_fmt(format_args!("Bandwidth (from args): {} kbps", k));
                Some(k)
            }
            None => prompt_bandwidth_once(),
        };

        SelectionResult { host_ids: ids, bandwidth_kbps: kbps }
    } else {
        let t = host_table.read().await;
        match TargetSelector::select(&t, our_ip) {
            Some(mut s) => {
                if let Some(k) = cfg.bandwidth_kbps {
                    s.bandwidth_kbps = Some(k);
                    logger.info_fmt(format_args!("Bandwidth (from args): {} kbps", k));
                }
                s
            }
            None => {
                logger.info_fmt(format_args!("No targets selected. Exiting."));
                return Ok(());
            }
        }
    };

    // ── Resolve final bandwidth ──────────────────────────────────────────────
    let kbps = match selection.bandwidth_kbps {
        Some(0) => {
            logger.error_fmt(format_args!(
                "Bandwidth 0 is not valid in gateway mode. \
                 Use a positive kbps value or omit --bandwidth for no cap."
            ));
            return Ok(());
        }
        Some(k) => k,
        None => 0,
    };

    // ── tc initialisation ────────────────────────────────────────────────────
    let mut tc = TcManager::new(&interface_name);

    match tc.init().await {
        Err(e) => {
            logger.error_fmt(format_args!("tc init failed: {e}"));
            std::process::exit(1);
        }
        Ok(()) => logger.info_fmt(format_args!(
            "tc: HTB + IFB shaping initialised on {}.", interface_name
        )),
    }

    if kbps > 0 {
        let table = host_table.read().await;
        for &id in &selection.host_ids {
            if let Some(entry) = table.get_by_id(id) {
                match tc.limit_host(id, entry.host.ip, kbps).await {
                    Ok(()) => logger.info_fmt(format_args!(
                        "tc: [{}] {} → {} kbps", id,
                        COLOR_WARN.paint(&entry.host.ip.to_string()), kbps,
                    )),
                    Err(e) => logger.error_fmt(format_args!(
                        "tc limit_host [{}] {}: {e}", id, entry.host.ip,
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
    let status_msg = if kbps > 0 {
        format!(
            "Shaping {} client(s) at {} kbps each. Press Ctrl-C or 'q' + Enter to stop.",
            selection.host_ids.len(), kbps,
        )
    } else {
        format!(
            "Monitoring {} client(s) (no cap). Press Ctrl-C or 'q' + Enter to stop.",
            selection.host_ids.len(),
        )
    };
    logger.info_fmt(format_args!("{}", COLOR_OK.paint(&status_msg)));

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

fn prompt_bandwidth_once() -> Option<u64> {
    use std::io::Write as _;
    print!("Bandwidth cap in kbps per client (leave blank = unlimited): ");
    std::io::stdout().flush().unwrap();
    let mut buf = String::new();
    if std::io::stdin().read_line(&mut buf).is_ok() {
        return TargetSelector::parse_bandwidth(buf.trim());
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_fields() {
        let cfg = GatewayModeConfig {
            interface:      Some("eth0".to_string()),
            bandwidth_kbps: Some(1024),
            targets:        vec!["10.0.0.1".to_string()],
        };
        assert_eq!(cfg.interface.as_deref(), Some("eth0"));
        assert_eq!(cfg.bandwidth_kbps, Some(1024));
        assert_eq!(cfg.targets.len(), 1);

        // Empty targets → full scan path
        let empty = GatewayModeConfig { interface: None, bandwidth_kbps: None, targets: vec![] };
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
}