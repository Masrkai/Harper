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
