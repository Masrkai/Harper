Feature: Gateway-mode client discovery
  As the gateway/AP operator
  I want clients discovered from the OS neighbour cache first
  So that shaping starts without an always-on ARP scan.

  Scenario: Cache-first discovery skips the active scan
    Given the kernel ARP cache has clients for interface eth0
    And our own IP is 192.168.1.1
    When gateway discovery runs on eth0
    Then clients are discovered from the cache
    And the active ARP scan is NOT used

  Scenario: Scan fallback when the cache is empty
    Given the kernel ARP cache is empty for interface eth0
    And our own IP is 192.168.1.1
    When gateway discovery runs on eth0
    Then 0 clients are discovered from the cache
    And the active ARP scan is used as a fallback
