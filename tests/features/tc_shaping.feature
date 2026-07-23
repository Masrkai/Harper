Feature: TcManager real shaping state
  As the bandwidth enforcer
  I want the TcManager to track per-host shaping state accurately
  So that I can query who is shaped and at what rate without shelling out.

  Scenario: Limiting a host records it as shaping with the correct kbps
    Given a fresh TcManager on interface eth0
    When host 1 with ip 10.0.0.5 is limited to 2048 kbps
    Then host 1 is shaping
    And host 1 current kbps is 2048

  Scenario: Blocking a host records it with kbps 0
    Given a fresh TcManager on interface eth0
    When host 2 with ip 10.0.0.9 is blocked
    Then host 2 is shaping
    And host 2 current kbps is 0

  Scenario: Updating an existing host mutates its rate without allocating a new slot
    Given a fresh TcManager on interface eth0
    And host 1 with ip 10.0.0.5 is limited to 2048 kbps
    When host 1 is limited to 512 kbps
    Then host 1 is shaping
    And host 1 current kbps is 512

  Scenario: Slot allocation is monotonic and skips the passthrough slot
    Given a fresh TcManager on interface eth0
    When host 1 with ip 10.0.0.5 is limited to 1000 kbps
    And host 2 with ip 10.0.0.6 is limited to 1000 kbps
    And host 3 with ip 10.0.0.7 is limited to 1000 kbps
    Then each host is assigned a distinct slot
    And no slot equals the passthrough slot 0xFFF

  Scenario: Removing a host clears its shaping state
    Given a fresh TcManager on interface eth0
    And host 1 with ip 10.0.0.5 is limited to 1000 kbps
    When host 1 is removed
    Then host 1 is not shaping

  Scenario: Querying an unknown host returns no kbps
    Given a fresh TcManager on interface eth0
    Then host 99 current kbps is none

  Scenario: Pool re-apply uses distinct leaf-handle offsets per device
    Given the pool slot is 0xFFE
    When a leaf is added for the egress nic
    And a leaf is added for ifb0
    Then the egress leaf handle equals 11fe:
    And the ifb0 leaf handle equals 12fe:
    And the two handles are different
    And the same offsets are used when removing the leaf
    And no orphan qdisc is left on ifb0 between pool re-applies

  Scenario: Pool re-apply tolerates the kernel's already-installed messages
    Given a pool re-apply for slot 0xFFE
    When the tc qdisc-add returns File exists
    And the tc qdisc-add returns Exclusivity flag on
    Then the qdisc-add wrapper does not propagate the error
    And subsequent pool re-applies do not leak RTNETLINK failures into Auto-MITM

  Scenario: Pool re-applies do not recreate the shared pool class
    Given a fresh TcManager on interface eth0
    And a pool rate of 600 kbps is applied with victim 10.0.0.5
    When a victim is added or removed, updating the pool
    Then the shared pool class is not deleted and recreated
    And only the pool ruleset is refreshed

