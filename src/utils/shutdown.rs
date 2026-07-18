// src/utils/shutdown.rs
//
// Shared shutdown signal handling used by both MITM mode (main.rs)
// and gateway mode (gateway_mode.rs).  Previously duplicated verbatim
// in both files.
//
// Fires a oneshot channel when either Ctrl-C or 'q' + Enter is received.
// The oneshot sender is wrapped in Arc<Mutex<Option<...>>> so both threads
// can safely race to send the signal — only the first one wins.

use std::sync::Arc;
use tokio::sync::oneshot;

/// Spawns a Ctrl-C listener thread and a stdin 'q' reader thread.
/// Returns a receiver that resolves when either signal arrives.
///
/// **Important:** Call this only *after* all interactive stdin prompts
/// (interface selector, target selector, bandwidth prompt) are complete.
/// Starting the 'q'-reader earlier causes it to race with those prompts
/// and consume their input, producing a spurious immediate exit.
pub fn spawn_shutdown_listener() -> oneshot::Receiver<()> {
    let (tx, rx) = oneshot::channel::<()>();
    let tx = Arc::new(std::sync::Mutex::new(Some(tx)));

    // Thread 1: Ctrl-C
    {
        let tx = Arc::clone(&tx);
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("[!] Failed to build shutdown runtime: {e}");
                    return;
                }
            };
            rt.block_on(tokio::signal::ctrl_c()).ok();
            fire(&tx);
        });
    }

    // Thread 2: 'q' + Enter on stdin
    {
        let tx = Arc::clone(&tx);
        std::thread::spawn(move || {
            use std::io::BufRead;
            let stdin = std::io::stdin();
            for line in stdin.lock().lines() {
                match line {
                    Ok(l) if l.trim().eq_ignore_ascii_case("q") => {
                        println!();
                        fire(&tx);
                        break;
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        });
    }

    rx
}

/// Sends the shutdown signal if it hasn't been sent yet.
fn fire(tx: &Arc<std::sync::Mutex<Option<oneshot::Sender<()>>>>) {
    if let Ok(mut guard) = tx.lock() {
        if let Some(sender) = guard.take() {
            let _ = sender.send(());
        }
    }
}
