pub mod calculator;
pub mod packet;

use std::net::Ipv4Addr;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpRange {
    pub start: Ipv4Addr,
    pub end: Ipv4Addr,
    pub network: Ipv4Addr,
    pub prefix_len: u8,
}

impl IpRange {
    pub fn from_cidr(cidr: &str) -> Result<Self, NetworkError> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err(NetworkError::InvalidCidr(cidr.to_string()));
        }

        let network = Ipv4Addr::from_str(parts[0])
            .map_err(|_| NetworkError::InvalidIp(parts[0].to_string()))?;
        let prefix_len: u8 = parts[1]
            .parse()
            .map_err(|_| NetworkError::InvalidPrefix(parts[1].to_string()))?;

        if prefix_len > 30 {
            return Err(NetworkError::PrefixTooLarge(prefix_len));
        }

        let mask = u32::MAX << (32 - prefix_len);
        let network_u32 = u32::from(network) & mask;
        let broadcast_u32 = network_u32 | !mask;

        let start = Ipv4Addr::from(network_u32 + 1);
        let end = Ipv4Addr::from(broadcast_u32 - 1);

        Ok(Self {
            start,
            end,
            network: Ipv4Addr::from(network_u32),
            prefix_len,
        })
    }

    pub fn iter(&self) -> IpRangeIterator {
        IpRangeIterator {
            current: u32::from(self.start),
            end: u32::from(self.end),
        }
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let ip_u32 = u32::from(ip);
        let start_u32 = u32::from(self.start);
        let end_u32 = u32::from(self.end);
        ip_u32 >= start_u32 && ip_u32 <= end_u32
    }
}

pub struct IpRangeIterator {
    current: u32,
    end: u32,
}

impl Iterator for IpRangeIterator {
    type Item = Ipv4Addr;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current > self.end {
            None
        } else {
            let ip = Ipv4Addr::from(self.current);
            self.current += 1;
            Some(ip)
        }
    }
}

#[derive(Debug)]
pub enum NetworkError {
    InvalidCidr(String),
    InvalidIp(String),
    InvalidPrefix(String),
    PrefixTooLarge(u8),
    InterfaceNotFound(String),
    PermissionDenied(String),
    SendError(String),
    RecvError(String),
}

impl std::fmt::Display for NetworkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCidr(s) => write!(f, "Invalid CIDR notation: {}", s),
            Self::InvalidIp(s) => write!(f, "Invalid IP address: {}", s),
            Self::InvalidPrefix(s) => write!(f, "Invalid prefix length: {}", s),
            Self::PrefixTooLarge(n) => write!(f, "Prefix length {} too large for host scanning", n),
            Self::InterfaceNotFound(s) => write!(f, "Interface {} not found", s),
            Self::PermissionDenied(s) => write!(f, "Permission denied: {}. Run as root?", s),
            Self::SendError(s) => write!(f, "Send error: {}", s),
            Self::RecvError(s) => write!(f, "Receive error: {}", s),
        }
    }
}

impl std::error::Error for NetworkError {}
