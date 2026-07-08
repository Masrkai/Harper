# harper

A network tool for bandwidth shaping and traffic management on local networks, written in Rust.

---

## What it does

harper sits between devices on your network and the internet, giving you control over who gets how much bandwidth. It can throttle a connection to a specific speed, block it entirely, or leave it untouched on a per-device basis.

It operates in two modes:

- **MITM mode**  harper positions itself between a target device and the gateway using ARP spoofing, without needing to be the actual router.
- **Gateway mode**  If you *are* the router or hotspot, harper shapes traffic directly without any ARP manipulation.

---

## Requirements

- Linux
- Root privileges
- A wired or wireless network interface

---

## Legal

This software is provided for **educational and research purposes only**. You are solely responsible for ensuring your use complies with all applicable laws. Only use harper on networks you own or have explicit written permission to test.

See [LICENSE](./LICENSE) for the full MIT license terms.

Also a statement from the author exist in [Legal Notice](Docs/legality.md)

---

## License

MIT © 2026 Masrkai
