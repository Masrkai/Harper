use std::fs;

#[derive(Debug)]
pub struct NetworkInterface {
    pub name: String,
    pub kind: InterfaceKind,
    pub is_up: bool,
    pub mac: Option<String>,
}

#[derive(Debug, PartialEq)]
pub enum InterfaceKind {
    Wireless, // wlan*
    Ethernet, // eth*
    Other,
}

impl InterfaceKind {
    pub fn from_name(name: &str) -> Self {
        if name.starts_with("wlan")
            || name.starts_with("wlp")
            || name.starts_with("wlo")
            || name.starts_with("wl")
        {
            Self::Wireless
        } else if name.starts_with("eth")
            || name.starts_with("enp")
            || name.starts_with("eno")
            || name.starts_with("ens")
        {
            Self::Ethernet
        } else {
            Self::Other
        }
    }
}

/// Reads a trimmed string from a sysfs file, returns None on any error.
#[inline]
fn read_sysfs(path: &str) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_owned())
}

/// Returns true if the interface operational state is "up".
#[inline]
fn is_up(iface: &str) -> bool {
    read_sysfs(&format!("/sys/class/net/{}/operstate", iface))
        .map(|s| s == "up")
        .unwrap_or(false)
}

/// Reads the MAC address for an interface.
#[inline]
fn mac_address(iface: &str) -> Option<String> {
    read_sysfs(&format!("/sys/class/net/{}/address", iface))
}

/// Scans /sys/class/net and returns all detected interfaces.
/// Filters to wireless and ethernet only if `only_wlan_eth` is true.
pub fn scan(only_wlan_eth: bool) -> Vec<NetworkInterface> {
    let entries = match fs::read_dir("/sys/class/net") {
        Ok(e) => e,
        Err(_) => return vec![],
    };

    entries
        .filter_map(|entry| {
            let name = entry.ok()?.file_name().into_string().ok()?;
            let kind = InterfaceKind::from_name(&name);
            if only_wlan_eth && kind == InterfaceKind::Other {
                return None;
            }
            Some(NetworkInterface {
                is_up: is_up(&name),
                mac: mac_address(&name),
                kind,
                name,
            })
        })
        .collect()
}
