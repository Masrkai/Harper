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
    And the attacker keeps the rest of the line rate

  Scenario: MITM mode applies pool across selected victims excluding the gateway
    Given the discovered hosts
      | ip          | mac               | is_gateway |
      | 192.168.1.1 | AA:BB:CC:00:00:01 | true       |
      | 192.168.1.5 | AA:BB:CC:00:00:02 | false      |
      | 192.168.1.6 | AA:BB:CC:00:00:03 | false      |
    When MITM pool mode is applied with 1000 kbps
    Then one shared class of 1000 kbps is created for 192.168.1.5 and 192.168.1.6
    And the gateway 192.168.1.1 is not pooled

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
