pub mod ebpf;
pub mod engine;
#[cfg(test)]
pub(crate) mod mock;

pub use engine::{ForwardRule, ForwarderCommand};

use crate::host::table::HostId;
use pnet::datalink::MacAddr;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};

/// Abstraction over the two MITM relay backends:
/// - `Userspace`: the legacy pnet `PacketForwarder` (default).
/// - `Kernel`: the in-kernel eBPF tc relay (selected by `--kernel`).
///
/// Both expose the same enable/disable semantics so callers (main.rs, the
/// dynamic `--all` manager) don't care which is active.
pub enum RelayHandle {
    Userspace(mpsc::Sender<ForwarderCommand>),
    Kernel(Arc<Mutex<ebpf::KernelRelay>>),
}

impl Clone for RelayHandle {
    fn clone(&self) -> Self {
        match self {
            RelayHandle::Userspace(tx) => RelayHandle::Userspace(tx.clone()),
            RelayHandle::Kernel(r) => RelayHandle::Kernel(Arc::clone(r)),
        }
    }
}

impl RelayHandle {
    /// Enable relay for a victim: frames from `victim_mac` are rewritten toward
    /// `gateway_mac`, and vice versa. `victim_ip` is carried for observability
    /// (used by the userspace path / tests).
    pub async fn enable(
        &self,
        id: HostId,
        victim_ip: Ipv4Addr,
        victim_mac: MacAddr,
        gateway_mac: MacAddr,
    ) {
        match self {
            RelayHandle::Userspace(tx) => {
                let _ = tx
                    .send(ForwarderCommand::Enable(ForwardRule {
                        host_id: id,
                        victim_ip,
                        victim_mac,
                        gateway_ip: Ipv4Addr::UNSPECIFIED,
                        gateway_mac,
                        our_mac: MacAddr::zero(),
                    }))
                    .await;
            }
            RelayHandle::Kernel(r) => {
                r.lock().await.enable(id, victim_mac, gateway_mac).await;
            }
        }
    }

    /// Disable relay for a single victim.
    pub async fn disable(&self, id: HostId) {
        match self {
            RelayHandle::Userspace(tx) => {
                let _ = tx.send(ForwarderCommand::Disable(id)).await;
            }
            RelayHandle::Kernel(r) => {
                r.lock().await.disable(id).await;
            }
        }
    }

    /// Disable relay for all victims.
    pub async fn disable_all(&self) {
        match self {
            RelayHandle::Userspace(tx) => {
                let _ = tx.send(ForwarderCommand::DisableAll).await;
            }
            RelayHandle::Kernel(r) => {
                r.lock().await.disable_all().await;
            }
        }
    }

    /// True when the kernel eBPF backend is active.
    pub fn is_kernel(&self) -> bool {
        matches!(self, RelayHandle::Kernel(_))
    }
}
