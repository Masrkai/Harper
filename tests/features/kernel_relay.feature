Feature: Kernel eBPF relay backend
  Harper can offload the MITM packet relay from the userspace PacketForwarder
  to an in-kernel eBPF tc program. Kernel relay (tc redirect) is the default;
  pass --userland to revert to userspace forwarding.

  Scenario: The --kernel flag selects the eBPF relay backend
    When the user runs harper with --kernel
    Then the eBPF tc ingress program is attached on the interface
    And victim uplink/downlink next-hop MACs are installed into the BPF map
    And the userspace PacketForwarder is not started

  Scenario: --userland is rejected alongside --gateway-mode
    When the user runs harper with --userland and --gateway-mode
    Then harper exits with an error before opening raw sockets

  Scenario: Victim enable populates the next-hop map both directions
    Given a victim with MAC AA:BB:CC:00:00:02 and gateway MAC 58:BA:D4:8E:37:2A
    When relay is enabled for the victim
    Then the BPF map maps AA:BB:CC:00:00:02 to 58:BA:D4:8E:37:2A
    And the BPF map maps 58:BA:D4:8E:37:2A to AA:BB:CC:00:00:02

  Scenario: Victim disable removes the next-hop mappings
    Given a previously-enabled victim
    When relay is disabled for the victim
    Then the BPF map no longer contains either MAC

  Scenario: Map miss drops the frame instead of forwarding to kernel stack
    Given a frame addressed to the attacker MAC
    But the source MAC is not in the harper_map
    When the eBPF program runs
    Then the frame is dropped with TC_ACT_SHOT
    And the kernel network stack never processes it

  Scenario: LRU hash map evicts oldest entry when full
    Given the harper_map uses LRU_HASH instead of plain HASH
    And max_entries is 4096
    When the map reaches capacity
    Then the oldest entry is automatically evicted
    And no userspace cleanup is needed

  Scenario: Kernel relay redirects via devmap
    Given the eBPF program includes a DEV map named egress_iface_map
    And the DEV map entry 0 stores the ifindex of the relay interface
    When a frame is matched for relay
    Then bpf_redirect_map redirects to the egress of the interface
    And TC_ACT_REDIRECT is returned instead of TC_ACT_OK

  Scenario: XDP preferred when available
    Given the interface supports XDP (xdp_features non-zero)
    When the user runs harper with --xdp
    Then the XDP eBPF program is attached
    And the DEVMAP redirects without SKB allocation

  Scenario: Falls back to tc redirect when XDP unsupported
    Given the interface does not support XDP
    When the user runs harper with --kernel (or default)
    Then tc redirect is attempted first
    And if that fails, tc legacy (TC_ACT_OK) is used instead
