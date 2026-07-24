// src/forwarder/backend.rs
//
// Defines the NetBackend trait for swappable network relay backends
// (Kernel eBPF vs In-Process Mock) per the declarative testing strategy.

use pnet::datalink::MacAddr;
use std::net::Ipv4Addr;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use crate::host::table::HostId;
use crate::forwarder::RelayHandle;

pub trait NetBackend: Send + Sync {
    fn name(&self) -> &'static str;
    async fn enable(&mut self, id: HostId, victim_ip: Ipv4Addr, victim_mac: MacAddr, gateway_mac: MacAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    async fn disable(&mut self, id: HostId) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    async fn disable_all(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    async fn read_map_snapshot(&self) -> Result<HashMap<String, String>, Box<dyn std::error::Error + Send + Sync>>;
}

pub struct KernelNetBackend {
    handle: RelayHandle,
}

impl KernelNetBackend {
    pub fn new(handle: RelayHandle) -> Self {
        Self { handle }
    }
}

impl NetBackend for KernelNetBackend {
    fn name(&self) -> &'static str {
        if self.handle.is_kernel() { "kernel-ebpf" } else { "userspace-pnet" }
    }

    async fn enable(&mut self, id: HostId, victim_ip: Ipv4Addr, victim_mac: MacAddr, gateway_mac: MacAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.handle.enable(id, victim_ip, victim_mac, gateway_mac).await;
        Ok(())
    }

    async fn disable(&mut self, id: HostId) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.handle.disable(id).await;
        Ok(())
    }

    async fn disable_all(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.handle.disable_all().await;
        Ok(())
    }

    async fn read_map_snapshot(&self) -> Result<HashMap<String, String>, Box<dyn std::error::Error + Send + Sync>> {
        let mut map = HashMap::new();
        map.insert("backend".to_string(), self.name().to_string());
        Ok(map)
    }
}

/// In-process MockBackend for fast unit tests without root or kernel dependencies.
pub struct MockNetBackend {
    rules: Arc<Mutex<HashMap<HostId, (Ipv4Addr, MacAddr, MacAddr)>>>,
}

impl MockNetBackend {
    pub fn new() -> Self {
        Self {
            rules: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl NetBackend for MockNetBackend {
    fn name(&self) -> &'static str {
        "mock"
    }

    async fn enable(&mut self, id: HostId, victim_ip: Ipv4Addr, victim_mac: MacAddr, gateway_mac: MacAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut rules = self.rules.lock().await;
        rules.insert(id, (victim_ip, victim_mac, gateway_mac));
        Ok(())
    }

    async fn disable(&mut self, id: HostId) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut rules = self.rules.lock().await;
        rules.remove(&id);
        Ok(())
    }

    async fn disable_all(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut rules = self.rules.lock().await;
        rules.clear();
        Ok(())
    }

    async fn read_map_snapshot(&self) -> Result<HashMap<String, String>, Box<dyn std::error::Error + Send + Sync>> {
        let rules = self.rules.lock().await;
        let mut map = HashMap::new();
        map.insert("active_rules".to_string(), rules.len().to_string());
        for (id, (ip, vm, gm)) in rules.iter() {
            map.insert(format!("host_{id}"), format!("ip={ip}, victim_mac={vm}, gateway_mac={gm}"));
        }
        Ok(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    pub enum ScenarioAction {
        EnableHost {
            id: HostId,
            ip: Ipv4Addr,
            victim_mac: MacAddr,
            gateway_mac: MacAddr,
        },
        DisableHost {
            id: HostId,
        },
        AssertActiveRules {
            expected_count: usize,
        },
    }

    #[tokio::test]
    async fn test_mock_backend_lifecycle() {
        let mut backend = MockNetBackend::new();
        assert_eq!(backend.name(), "mock");

        let id: HostId = 1;
        let ip = Ipv4Addr::new(192, 168, 1, 10);
        let vm = MacAddr(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);
        let gm = MacAddr(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);

        backend.enable(id, ip, vm, gm).await.unwrap();
        let snap = backend.read_map_snapshot().await.unwrap();
        assert_eq!(snap.get("active_rules").unwrap(), "1");

        backend.disable(id).await.unwrap();
        let snap2 = backend.read_map_snapshot().await.unwrap();
        assert_eq!(snap2.get("active_rules").unwrap(), "0");
    }

    #[tokio::test]
    async fn test_declarative_scenario_runner() {
        let mut backend = MockNetBackend::new();
        let actions = vec![
            ScenarioAction::AssertActiveRules { expected_count: 0 },
            ScenarioAction::EnableHost {
                id: 1,
                ip: Ipv4Addr::new(10, 0, 0, 5),
                victim_mac: MacAddr(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF),
                gateway_mac: MacAddr(0x11, 0x22, 0x33, 0x44, 0x55, 0x66),
            },
            ScenarioAction::AssertActiveRules { expected_count: 1 },
            ScenarioAction::DisableHost { id: 1 },
            ScenarioAction::AssertActiveRules { expected_count: 0 },
        ];

        for action in actions {
            match action {
                ScenarioAction::EnableHost { id, ip, victim_mac, gateway_mac } => {
                    backend.enable(id, ip, victim_mac, gateway_mac).await.unwrap();
                }
                ScenarioAction::DisableHost { id } => {
                    backend.disable(id).await.unwrap();
                }
                ScenarioAction::AssertActiveRules { expected_count } => {
                    let snap = backend.read_map_snapshot().await.unwrap();
                    let count: usize = snap.get("active_rules").unwrap().parse().unwrap();
                    assert_eq!(count, expected_count);
                }
            }
        }
    }

    #[test]
    fn test_load_topology_toml() {
        let path = std::path::Path::new("tests/topologies/two-hosts.toml");
        if path.exists() {
            let content = std::fs::read_to_string(path).unwrap();
            let parsed: toml::Value = toml::from_str(&content).unwrap();
            insta::assert_debug_snapshot!("two-hosts-topology", parsed);
        }
    }

    #[test]
    fn test_load_scenario_toml() {
        let path = std::path::Path::new("tests/scenarios/tcp-forward.toml");
        if path.exists() {
            let content = std::fs::read_to_string(path).unwrap();
            let parsed: toml::Value = toml::from_str(&content).unwrap();
            insta::assert_debug_snapshot!("tcp-forward-scenario", parsed);
        }
    }
}
