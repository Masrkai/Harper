use pnet::datalink::NetworkInterface;
use std::net::Ipv4Addr;

pub fn get_interface(name: &str) -> Option<NetworkInterface> {
    pnet::datalink::interfaces()
        .into_iter()
        .find(|i| i.name == name)
}

pub fn get_ipv4_addr(iface: &NetworkInterface) -> Option<Ipv4Addr> {
    iface.ips.iter().find_map(|ip| {
        if let std::net::IpAddr::V4(addr) = ip.ip() {
            Some(addr)
        } else {
            None
        }
    })
}
