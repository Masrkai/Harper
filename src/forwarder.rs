pub mod engine;

use crate::host::table::HostId;
use pnet::util::MacAddr;
use std::net::Ipv4Addr;

#[derive(Debug, Clone)] // <-- Add Clone here
pub struct ForwardRule {
    pub host_id: HostId,
    pub victim_ip: Ipv4Addr,
    pub victim_mac: MacAddr,
    pub gateway_ip: Ipv4Addr,
    pub gateway_mac: MacAddr,
    pub our_mac: MacAddr,
}

#[derive(Debug)]
pub enum ForwarderCommand {
    Enable(ForwardRule),
    Disable(HostId),
    DisableAll,
}
