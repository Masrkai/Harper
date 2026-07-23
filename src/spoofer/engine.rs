// src/spoofer/engine.rs
use crate::cli::color::palette::{INFO, OK, WARN, KEYWORD};
use crate::paint;
use super::{SpoofTarget, SpooferCommand, poison::PoisonLoop};
use crate::host::table::{HostState, HostTable};
use pnet::util::MacAddr;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc, oneshot};
use tokio::task::JoinHandle;

use std::net::Ipv4Addr;

pub struct SpooferEngine {
    our_mac: MacAddr,
    our_ip: Ipv4Addr,
    gateway_ip: std::net::Ipv4Addr,
    one_sided: bool,
    /// Name of the network interface. Each PoisonLoop opens its own
    /// independent socket on this interface — no shared sender mutex.
    interface_name: String,
    host_table: Arc<RwLock<HostTable>>,

    active_loops: HashMap<crate::host::table::HostId, PoisonHandle>,

    cmd_tx: mpsc::Sender<SpooferCommand>,
    cmd_rx: mpsc::Receiver<SpooferCommand>,
}

struct PoisonHandle {
    stop_tx: oneshot::Sender<()>,
    task: JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>,
}

impl SpooferEngine {
    pub fn new(
        our_mac: MacAddr,
        our_ip: Ipv4Addr,
        gateway_ip: std::net::Ipv4Addr,
        interface_name: impl Into<String>,
        host_table: Arc<RwLock<HostTable>>,
        one_sided: bool,
    ) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel(32);

        Self {
            our_mac,
            our_ip,
            gateway_ip,
            one_sided,
            interface_name: interface_name.into(),
            host_table,
            active_loops: HashMap::new(),
            cmd_tx,
            cmd_rx,
        }
    }

    pub fn command_sender(&self) -> mpsc::Sender<SpooferCommand> {
        self.cmd_tx.clone()
    }

    pub async fn run(mut self) {
        println!("{}", paint!(INFO, "[*] SpooferEngine started"));
        println!("    Gateway IP:  {}", paint!(KEYWORD, "{}", self.gateway_ip));
        println!("    Our MAC:     {}", paint!(KEYWORD, "{}", self.our_mac));
        println!("    Interface:   {}", paint!(KEYWORD, "{}", self.interface_name));

        while let Some(cmd) = self.cmd_rx.recv().await {
            match cmd {
                SpooferCommand::Start(target) => {
                    self.start_poison(target).await;
                }
                SpooferCommand::Stop(host_id) => {
                    self.stop_poison(host_id).await;
                }
                SpooferCommand::StopAll => {
                    self.stop_all().await;
                    break;
                }
            }
        }

        println!("{}", paint!(INFO, "[*] SpooferEngine shutting down"));
        self.stop_all().await;
    }

    async fn start_poison(&mut self, target: SpoofTarget) {
        let host_id = target.host_id;

        if self.active_loops.contains_key(&host_id) {
            println!("{}", paint!(WARN, "[!] Host {} is already being poisoned", host_id));
            return;
        }

        println!("{}", paint!(INFO, "[*] Starting ARP poison for host {}:", host_id));
        println!("    Victim:  {} @ {}", paint!(KEYWORD, "{}", target.victim_ip), paint!(KEYWORD, "{}", target.victim_mac));
        println!(
            "    Gateway: {} @ {}",
            paint!(KEYWORD, "{}", target.gateway_ip), paint!(KEYWORD, "{}", target.gateway_mac)
        );

        {
            let mut table = self.host_table.write().await;
            table.update_state(host_id, HostState::Poisoning);
        }

        let (stop_tx, stop_rx) = oneshot::channel();

        // Each PoisonLoop gets its own dedicated socket — no shared mutex.
        let poison_loop = PoisonLoop::new(
            self.interface_name.clone(),
            self.our_mac,
            self.our_ip,
            0, // interval_ms ignored; constants inside PoisonLoop are used
            self.one_sided,
        );

        let task = tokio::spawn(async move { poison_loop.run(target, stop_rx).await });

        self.active_loops
            .insert(host_id, PoisonHandle { stop_tx, task });
        println!(
            "{}",
            paint!(OK, "[+] Poison loop started for host {} (dedicated socket)", host_id)
        );
    }

    async fn stop_poison(&mut self, host_id: crate::host::table::HostId) {
        if let Some(handle) = self.active_loops.remove(&host_id) {
            println!("{}", paint!(INFO, "[*] Stopping poison for host {}…", host_id));

            let _ = handle.stop_tx.send(());

            let abort_handle = handle.task.abort_handle();
            match tokio::time::timeout(std::time::Duration::from_secs(5), handle.task).await {
                Ok(Ok(_)) => {
                    println!("{}", paint!(OK, "[+] Poison stopped cleanly for host {}", host_id));
                }
                Ok(Err(e)) => {
                    eprintln!("[!] Poison task error for host {}: {}", host_id, e);
                }
                Err(_) => {
                    eprintln!("[!] Poison stop timeout for host {}", host_id);
                    abort_handle.abort();
                }
            }

            let mut table = self.host_table.write().await;
            table.update_state(host_id, HostState::Discovered);
        } else {
            println!("[!] Host {} is not being poisoned", host_id);
        }
    }

    async fn stop_all(&mut self) {
        let host_ids: Vec<_> = self.active_loops.keys().copied().collect();
        for id in host_ids {
            self.stop_poison(id).await;
        }
    }
}
