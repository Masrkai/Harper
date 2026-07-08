#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Delay between individual ARP sends within one pass (ms).
    pub send_interval_ms: u64,

    /// Number of full range sweeps.
    /// Extra passes catch devices that were asleep or dropped the first frame.
    pub passes: u32,

    /// Pause between consecutive passes (ms).
    /// Gives sleeping wireless clients time to wake and process earlier requests.
    pub inter_pass_delay_ms: u64,

    /// Minimum collection window *after* the last send finishes (ms).
    /// We never exit before this, even if the network looks quiet.
    pub post_send_min_ms: u64,

    /// Early-exit trigger: if no *new* host has been seen for this long (ms),
    /// consider the scan done (subject to post_send_min_ms).
    pub idle_cutoff_ms: u64,

    /// Hard ceiling — scan never runs longer than this regardless of activity.
    pub hard_timeout_secs: u64,

    /// Send a UDP probe to each IP before the first ARP pass to nudge
    /// 802.11 power-save clients out of their deepest sleep state.
    pub pre_wake: bool,
}

impl ScanConfig {
    /// Wired Ethernet: low latency, reliable delivery, no power-save.
    pub fn ethernet() -> Self {
        Self {
            send_interval_ms: 8,
            passes: 3,
            inter_pass_delay_ms: 1_500,
            post_send_min_ms: 4_000,
            idle_cutoff_ms: 2_000,
            hard_timeout_secs: 60,
            pre_wake: false, // no power-save clients on wired networks
        }
    }

    /// 802.11 wireless: higher latency, packet loss, power-save clients.
    pub fn wireless() -> Self {
        Self {
            send_interval_ms: 8,        // gentler pacing — AP queue can back up fast
            passes: 5,                  // extra sweeps for sleeping devices
            inter_pass_delay_ms: 3_000, // ≥ 1 beacon interval for power-save wakeup
            post_send_min_ms: 4_000,    // far clients can have 2–3 s RTT
            idle_cutoff_ms: 2_000,      // wireless is noisy; wait longer for stragglers
            hard_timeout_secs: 60,
            pre_wake: true, // probe before sweep on WiFi
        }
    }

    pub fn for_interface(name: &str) -> Self {
        if is_wireless_iface(name) {
            Self::wireless()
        } else {
            Self::ethernet()
        }
    }
}

pub(crate) fn is_wireless_iface(name: &str) -> bool {
    // Covers: wlan0, wlp3s0, wlo1, wl* (generic)
    name.starts_with("wlan")
        || name.starts_with("wlp")
        || name.starts_with("wlo")
        || name.starts_with("wl")
}
