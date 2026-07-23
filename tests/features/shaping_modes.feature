Feature: Gateway shaping modes
  As the gateway/AP operator
  I want flexible bandwidth policies
  So that I can share a pool or exclude the bottleneck link.

  Scenario: Pool mode shares one bandwidth class across all victims
    Given the selected victim IPs
      | ip          |
      | 10.0.0.5    |
      | 10.0.0.6    |
    When pool mode is applied with 500 kbps
    Then one shared class of 500 kbps is created for all victims
    And the local host keeps the rest of the line rate

  Scenario: Pool mode creates the shared class once and only refreshes rules on re-apply
    Given the selected victim IPs
      | ip          |
      | 10.0.0.5    |
    When pool mode is applied with 500 kbps
    And pool mode is re-applied for 10.0.0.5 and 10.0.0.6
    Then the shared class is created exactly once
    And the pool ruleset is refreshed twice

  Scenario: MITM mode applies pool across selected victims excluding the gateway
    Given the discovered hosts
      | ip          | mac               | is_gateway |
      | 192.168.1.1 | AA:BB:CC:00:00:01 | true       |
      | 192.168.1.5 | AA:BB:CC:00:00:02 | false      |
      | 192.168.1.6 | AA:BB:CC:00:00:03 | false      |
    When MITM pool mode is applied with 1000 kbps
    Then one shared class of 1000 kbps is created for 192.168.1.5 and 192.168.1.6
    And the gateway 192.168.1.1 is not pooled

  Scenario: MITM --all dynamically adds a late-joining victim to the shared pool
    Given the discovered hosts
      | ip          | mac               | is_gateway |
      | 192.168.1.1 | AA:BB:CC:00:00:01 | true       |
      | 192.168.1.5 | AA:BB:CC:00:00:02 | false      |
    When MITM pool mode is applied with 1000 kbps
    And a new device 192.168.1.7 with mac AA:BB:CC:00:00:04 joins the network
    Then the shared pool of 1000 kbps now covers 192.168.1.5, 192.168.1.6 and 192.168.1.7
    And the gateway 192.168.1.1 is not pooled

  Scenario: MITM --all auto-selects every non-gateway host without prompting
    Given the discovered hosts
      | ip          | mac               | is_gateway |
      | 192.168.1.1 | AA:BB:CC:00:00:01 | true       |
      | 192.168.1.5 | AA:BB:CC:00:00:02 | false      |
      | 192.168.1.6 | AA:BB:CC:00:00:03 | false      |
    When MITM --all mode selects targets
    Then the selected victim set is 192.168.1.5 and 192.168.1.6
    And the gateway 192.168.1.1 is excluded from the selection
    And no interactive target prompt is required

  Scenario: Uplink exclusion removes the bottleneck device from victims
    Given a known host with ip 10.0.0.1 and mac AA:BB:CC:00:00:01
    And the candidate victim pool contains 10.0.0.1 and 10.0.0.2
    When the uplink AA:BB:CC:00:00:01 is excluded
    Then the excluded victim set is 10.0.0.2

  Scenario: Uplink given as an IP excludes that device
    Given a known host with ip 10.0.0.1 and mac AA:BB:CC:00:00:01
    And the candidate victim pool contains 10.0.0.1 and 10.0.0.2
    When the uplink 10.0.0.1 is excluded
    Then the excluded victim set is 10.0.0.2

  Scenario: Unresolvable uplink falls back to excluding self
    Given a known host with ip 10.0.0.1 and mac AA:BB:CC:00:00:01
    And our own IP is 192.168.1.100
    When the uplink 10.9.9.9 is excluded
    Then the excluded IP is our own IP

  Scenario: Dynamic scaling of shared pool bandwidth when victims join and leave
    Given a pool of 1000 kbps shared across victims 192.168.1.5 and 192.168.1.6
    When victim 192.168.1.7 joins the pool
    Then the pool ruleset updates to cover 192.168.1.5, 192.168.1.6 and 192.168.1.7
    When victim 192.168.1.6 leaves the pool
    Then the pool ruleset updates to cover only 192.168.1.5 and 192.168.1.7

