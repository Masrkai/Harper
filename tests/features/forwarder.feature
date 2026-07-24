Feature: Forwarder packet path
  As the MITM packet forwarder
  I want reliable delivery of rewritten frames
  So that transient kernel buffer exhaustion does not drop victim traffic.

  Scenario: A large IPv4 frame is fragmented to fit the MTU
    Given an IPv4 frame with a 9000-byte payload
    When it is relayed through the forwarder
    Then more than one frame is produced
    And every fragment is at most 1514 bytes

  Scenario: A WouldBlock error triggers a retry that succeeds
    Given a sender that fails with WouldBlock once
    When a frame is relayed through the forwarder
    Then exactly one frame is delivered

  Scenario: Four ENOBUFS errors exhaust the retry budget
    Given a sender that fails with ENOBUFS four times
    When a frame is relayed through the forwarder
    Then zero frames are delivered
    And the sender was attempted exactly four times

  Scenario: A fatal error is not retried
    Given a sender that fails with a fatal error once
    When a frame is relayed through the forwarder
    Then the sender was attempted exactly once
    And zero frames are delivered

   Scenario: Resilient delivery of super-frames under intermittent ENOBUFS backpressure
     Given a super-frame exceeding standard MTU with intermittent ENOBUFS errors
     When relayed through the forwarder with retry backoff
     Then all fragments are successfully delivered within retry limits

   Scenario: Forwarded IPv4 packet has its TTL decremented
     Given an IPv4 frame with TTL 64
     When it is relayed through the forwarder
     Then the delivered frame has TTL 63

   Scenario: Forwarded IPv4 packet with TTL of 1 is dropped
     Given an IPv4 frame with TTL 1
     When it is relayed through the forwarder
     Then zero frames are delivered


