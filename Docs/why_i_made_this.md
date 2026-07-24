A network constraint in my local environment led me down a rabbit hole that fundamentally reshaped my understanding of network security architecture.

Faced with a heavily metered ISP data cap and uncooperative household members consuming excessive bandwidth, I needed a way to prioritize my work traffic. When logical cooperation failed, I turned to technical enforcement. Drawing on my knowledge of the TCP/IP stack, I developed an ARP spoofing utility to rate-limit and control rogue devices on the network.

Building this tool required exploiting the foundational design of IPv4. By broadcasting spoofed Address Resolution Protocol packets, I could easily intercept traffic and perform a Man-in-the-Middle (MitM) attack. The ease of this execution raised a critical question: if local network protocols are this trivially exploitable, alongside the rise of endpoint supply chain attacks, why hasn't the industry implemented a cryptographically secure successor something akin to an "IPv4++"?

The answer lies in a fascinating, albeit frustrating, historical context.

When ARP was engineered in the early 1980s, the internet was a closed ecosystem of academic and military institutions. The protocol operates on a foundational assumption: "If you are on the local network, you are trusted." ARP is stateless and unauthenticated. A device broadcasts a query, and any device can respond with a spoofed MAC address. The victim accepts this blindly. There is no cryptographic verification. Why? Because integrating authentication necessitates a key-exchange mechanism, adding overhead to a protocol designed for minimalism. By the time the internet became a public, untrusted entity, IPv4 was too deeply entrenched to retrofit.

One might assume IPv6 resolved this, but the networking community essentially replicated the flaw. IPv6 replaced ARP with the Neighbor Discovery Protocol (NDP) via ICMPv6. Devices still utilize Stateless Address Autoconfiguration (SLAAC), trusting unauthenticated Router Advertisements (RAs) to configure their routing. The IETF opted against mandating a Public Key Infrastructure (PKI) for local networks, assuming Layer 2 security (like Wi-Fi passwords) or physical isolation would suffice. However, a shared WPA key does nothing to protect against rogue endpoints on the same LAN.

Instead of securing the network layer, the industry applied mitigations at higher layers:

- Data Link Layer: Enterprise environments implemented Dynamic ARP Inspection (DAI) and DHCP Snooping. However, this requires managed hardware absent in consumer networks.
- Application Layer: The pervasive adoption of TLS and HTTPS ensures that even if a MitM attack succeeds via ARP spoofing, the payload remains encrypted.
- Network Segmentation: Architectures shifted toward VLANs and 802.1X to isolate untrusted devices.

A protocol called SEND (Secure Neighbor Discovery Protocol) was actually developed to fix this. It uses Cryptographically Generated Addresses (CGAs) to verify that a device holds the cryptographic key for the IP it claims. So why isn't SEND ubiquitous? OS vendors largely ignored it, viewing it as too resource-intensive for consumer hardware. Furthermore, as supply chain attacks have demonstrated, the threat has moved up the stack. Securing local transport is irrelevant when the endpoints themselves smart TVs, IoT devices, and mobile applications are compromised.

Ultimately, my journey mirrored the evolution of modern cybersecurity. I found a problem, built a tool to exploit it, and realized the foundation was fundamentally broken. I didn't fail to find "IPv4++"; it simply doesn't exist in mainstream deployment because the industry decided it was more pragmatic to abandon the concept of a trusted local network entirely.

This is the core tenet of Zero Trust architecture: Never trust, always verify. The modern architectural assumption is that the local network is already compromised. Therefore, every request must be authenticated, authorized, and encrypted, regardless of network position.
