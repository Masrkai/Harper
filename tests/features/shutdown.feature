Feature: Graceful Shutdown and Network Restoration
  As the operator running Harper
  I want a graceful shutdown sequence on SIGINT
  So that ARP state, forwarder, nftables, tc qdiscs, and kernel sysctls are restored correctly.

  Scenario: Ctrl-C triggers full state restoration in reverse order
    Given the application is actively managing 3 hosts
    And kernel state and nftables and tc shaping are active
    When the shutdown manager executes cleanup
    Then cleanup runs across all components in reverse order
    And ARP restore packets are sent to victims
    And nftables rules are revoked
    And tc qdiscs are removed
    And kernel state is restored
