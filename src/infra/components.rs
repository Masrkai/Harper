use crate::infra::Cleanupable;
use crate::utils::proc::read_proc;
use std::process::Command;

pub struct KernelState {
    pub ip_forward: Option<String>,
    pub send_redirects: Option<String>,
    pub rp_filter_all: Option<String>,
    pub interface: String,
    /// Additional sysctls tuned for high-performance MITM (save → set → restore).
    extra: Vec<SysctlEntry>,
}

/// A single sysctl whose original value is saved so it can be restored on exit.
struct SysctlEntry {
    path: String,
    original: Option<String>,
}

impl KernelState {
    pub fn enable(interface: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let redirect_path = format!("/proc/sys/net/ipv4/conf/{}/send_redirects", interface);
        let accept_redirects_iface =
            format!("/proc/sys/net/ipv4/conf/{interface}/accept_redirects");

        // ── Additional MITM tuning (best-effort; save original → set → restore)
        let mut extra: Vec<SysctlEntry> = Vec::new();
        let mut tune = |path: &str, val: &str| {
            extra.push(SysctlEntry {
                path: path.to_string(),
                original: read_proc(path),
            });
            let _ = std::fs::write(path, format!("{val}\n"));
        };
        tune("/proc/sys/net/ipv4/conf/all/accept_redirects", "0");
        tune("/proc/sys/net/ipv4/conf/default/accept_redirects", "0");
        tune(&accept_redirects_iface, "0");
        tune("/proc/sys/net/ipv4/tcp_mtu_probing", "1");
        tune("/proc/sys/net/core/rmem_max", "16777216");
        tune("/proc/sys/net/core/wmem_max", "16777216");
        tune("/proc/sys/net/core/rmem_default", "16777216");
        tune("/proc/sys/net/core/wmem_default", "16777216");
        tune("/proc/sys/net/ipv4/ip_local_port_range", "10000 65535");
        tune("/proc/sys/net/netfilter/nf_conntrack_tcp_loose", "1");

        let state = Self {
            ip_forward: read_proc("/proc/sys/net/ipv4/ip_forward"),
            send_redirects: read_proc(&redirect_path),
            rp_filter_all: read_proc("/proc/sys/net/ipv4/conf/all/rp_filter"),
            interface: interface.to_owned(),
            extra,
        };

        // ── Standard MITM tuning
        std::fs::write("/proc/sys/net/ipv4/ip_forward", "0\n")?;

        let _ = std::fs::write(&redirect_path, "0\n");
        let _ = std::fs::write("/proc/sys/net/ipv4/conf/all/send_redirects", "0\n");

        std::fs::write("/proc/sys/net/ipv4/conf/all/rp_filter", "0\n")?;
        let _ = std::fs::write(
            &format!("/proc/sys/net/ipv4/conf/{}/rp_filter", interface),
            "0\n",
        );

        Ok(state)
    }

    pub fn restore(&self) {
        let redirect_path = format!("/proc/sys/net/ipv4/conf/{}/send_redirects", self.interface);
        restore_sysctl("/proc/sys/net/ipv4/ip_forward", self.ip_forward.as_deref());
        restore_sysctl(&redirect_path, self.send_redirects.as_deref());
        restore_sysctl("/proc/sys/net/ipv4/conf/all/send_redirects", Some("1\n"));
        restore_sysctl(
            "/proc/sys/net/ipv4/conf/all/rp_filter",
            self.rp_filter_all.as_deref(),
        );
        restore_sysctl(
            &format!("/proc/sys/net/ipv4/conf/{}/rp_filter", self.interface),
            self.rp_filter_all.as_deref(),
        );
        for entry in &self.extra {
            restore_sysctl(&entry.path, entry.original.as_deref());
        }
    }
}

/// Writes a sysctl value, surfacing failures instead of silently ignoring them.
/// A failed restore (e.g. of ip_forward) could leave the host in an unsafe
/// state, so the operator must be told. A `None` value (original unreadable)
/// is left untouched rather than written.
fn restore_sysctl(path: &str, value: Option<&str>) {
    let Some(value) = value else {
        eprintln!("[!] Skipping restore of sysctl {path}: original value was unreadable");
        return;
    };
    if let Err(e) = std::fs::write(path, value) {
        eprintln!("[!] Failed to restore sysctl {path}: {e}");
    }
}

impl Cleanupable for KernelState {
    fn cleanup(
        &mut self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), Box<dyn std::error::Error>>> + Send + '_>,
    > {
        let kernel_state = self;
        Box::pin(async move {
            kernel_state.restore();
            Ok(())
        })
    }
}

pub struct NftGate {
    pub rpfilter_handle: Option<u64>,
}

impl NftGate {
    pub fn install(interface: &str) -> Self {
        let rule = format!(
            "add rule inet nixos-fw rpfilter-allow iifname \"{iface}\" accept",
            iface = interface,
        );

        let ok = Command::new("nft")
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

    pub fn revoke(&self) {
        if let Some(handle) = self.rpfilter_handle {
            let _ = Command::new("nft")
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

impl Cleanupable for NftGate {
    fn cleanup(
        &mut self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), Box<dyn std::error::Error>>> + Send + '_>,
    > {
        let nft_gate = self;
        Box::pin(async move {
            nft_gate.revoke();
            Ok(())
        })
    }
}

fn last_rule_handle(family: &str, table: &str, chain: &str) -> Option<u64> {
    let out = Command::new("nft")
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
