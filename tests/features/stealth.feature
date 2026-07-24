Feature: Stealth tests validation
  As an auditor
  I want rigorous tests for non-IP traffic passthrough, fragmented packets, and gradual ARP restoration
  So that Harper's stealth features remain completely transparent and robust.

  Scenario: Non-IP traffic such as ARP frames pass through safely
    Given an ARP frame
    When it is relayed through the forwarder
    Then the frame is delivered unmodified without casting errors

  Scenario: Fragmented IPv4 packets have TTL decremented across fragments
    Given an IPv4 fragmented frame set with TTL 64
    When it is relayed through the forwarder
    Then all fragments have their TTL decremented to 63 and valid checksums

  Scenario: Gradual ARP restoration taper runs over increasing intervals
    Given active ARP poison state for a victim
    When graceful shutdown initiates ARP restoration
    Then restore packets are sent with increasing tapered delays
