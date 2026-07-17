Feature: Client discovery from the kernel ARP cache
  As the gateway/AP operator
  I want clients discovered from the OS neighbour table
  So that shaping starts instantly without an active ARP scan.

  Scenario: Discovering clients from a populated ARP cache
    Given the kernel ARP cache contains
      | ip             | mac                 | iface |
      | 192.168.1.10   | AA:BB:CC:DD:EE:01   | eth0  |
      | 192.168.1.11   | AA:BB:CC:DD:EE:02   | eth0  |
    And our own IP is 192.168.1.1
    When we discover clients on interface eth0
    Then 2 clients are discovered
    And 192.168.1.10 is among the discovered clients
    And 192.168.1.11 is among the discovered clients

  Scenario: Excluding our own IP from discovery
    Given the kernel ARP cache contains
      | ip             | mac                 | iface |
      | 192.168.1.1    | AA:BB:CC:DD:EE:00   | eth0  |
      | 192.168.1.10   | AA:BB:CC:DD:EE:01   | eth0  |
    And our own IP is 192.168.1.1
    When we discover clients on interface eth0
    Then 1 client is discovered
    And 192.168.1.10 is among the discovered clients

  Scenario: Filtering by interface
    Given the kernel ARP cache contains
      | ip             | mac                 | iface |
      | 10.0.0.5       | BB:BB:BB:BB:BB:BB   | wlan0 |
      | 192.168.1.10   | AA:BB:CC:DD:EE:01   | eth0  |
    And our own IP is 192.168.1.1
    When we discover clients on interface eth0
    Then 1 client is discovered
    And 192.168.1.10 is among the discovered clients

  Scenario: Discovering from an empty ARP cache
    Given the kernel ARP cache is empty
    And our own IP is 192.168.1.1
    When we discover clients on interface eth0
    Then 0 clients are discovered
