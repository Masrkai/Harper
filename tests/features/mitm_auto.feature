Feature: MITM auto victim lifecycle
  As the --all mode operator
  I want Harper to dynamically pull devices into the MITM
  So that new hosts are poisoned, forwarded and shaped without manual input.

  Scenario: Seeding victim ids marks them as managed
    Given a host table with 192.168.1.5 and 192.168.1.6
    When the manager is seeded with both host ids
    Then both hosts are managed

  Scenario: A seen device that is not the gateway is added as a victim
    Given a host table with 192.168.1.5
    And the gateway is 192.168.1.1
    When 192.168.1.5 with mac AA:BB:CC:00:00:02 is seen on the wire
    Then a forward Enable command is sent for 192.168.1.5
    And a spoof Start command is sent for 192.168.1.5

  Scenario: The gateway is never added as a victim
    Given a host table with 192.168.1.1
    And the gateway is 192.168.1.1
    When 192.168.1.1 with mac AA:BB:CC:00:00:01 is seen on the wire
    Then no forward Enable command is sent
    And no spoof Start command is sent

  Scenario: A re-seen already-managed device is de-duplicated
    Given a host table with 192.168.1.5
    And the gateway is 192.168.1.1
    When 192.168.1.5 with mac AA:BB:CC:00:00:02 is seen on the wire twice
    Then exactly one forward Enable command is sent for 192.168.1.5

  Scenario: A late-joining device grows the managed set
    Given a host table with 192.168.1.5 and 192.168.1.7
    And the gateway is 192.168.1.1
    When 192.168.1.5 with mac AA:BB:CC:00:00:02 is seen
    And 192.168.1.7 with mac AA:BB:CC:00:00:07 is seen
    Then a forward Enable command is sent for 192.168.1.5
    And a forward Enable command is sent for 192.168.1.7
