Feature: Kernel eBPF relay backend
  Harper can offload the MITM packet relay from the userspace PacketForwarder
  to an in-kernel eBPF tc program via the --kernel flag. The userspace path
  remains the default so both can be compared.

  Scenario: The --kernel flag selects the eBPF relay backend
    When the user runs harper with --kernel
    Then the eBPF tc ingress program is attached on the interface
    And victim uplink/downlink next-hop MACs are installed into the BPF map
    And the userspace PacketForwarder is not started

  Scenario: --kernel is rejected alongside --gateway-mode
    When the user runs harper with --kernel and --gateway-mode
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
