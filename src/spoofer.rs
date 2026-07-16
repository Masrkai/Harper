pub mod engine;
pub mod poison;

pub use engine::SpooferEngine;
// pub use poison::PoisonPacket;

use crate::host::table::HostId;
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub struct SpoofTarget {
    pub host_id: HostId,
    pub victim_ip: Ipv4Addr,
    pub victim_mac: MacAddr,
    pub gateway_ip: Ipv4Addr,
    pub gateway_mac: MacAddr,
}

impl SpoofTarget {
    pub fn new(
        host_id: HostId,
        victim_ip: Ipv4Addr,
        victim_mac: MacAddr,
        gateway_ip: Ipv4Addr,
        gateway_mac: MacAddr,
    ) -> Self {
        Self {
            host_id,
            victim_ip,
            victim_mac,
            gateway_ip,
            gateway_mac,
        }
    }
}

#[derive(Debug)]
pub enum SpooferCommand {
    Start(SpoofTarget),
    Stop(HostId),
    StopAll,
}
