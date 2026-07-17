Feature: nftables mark rules for traffic shaping
  As the shaper
  I want victim traffic marked so tc HTB classes can classify it
  So that bandwidth limits are applied correctly.

  Scenario: Per-host shaping marks each victim with its own slot
    Given a shaped host with id 1, ip 10.0.0.5, slot 7, mode Limited(2048)
    When the nft rules are built for per-host shaping
    Then the rules mark source 10.0.0.5 with 7
    And the rules mark destination 10.0.0.5 with 7 when its conntrack mark is 0

  Scenario: Blocked hosts are dropped
    Given a shaped host with id 1, ip 10.0.0.9, slot 9, mode Blocked
    When the nft rules are built for per-host shaping
    Then the rules drop source 10.0.0.9
    And the rules drop destination 10.0.0.9

  Scenario: Pool mode marks every victim with one shared mark
    Given the pool victims
      | ip          |
      | 10.0.0.5    |
      | 10.0.0.6    |
    When the nft rules are built for pool mode
    Then every victim is marked with the shared pool mark 4094
    And no per-host slot marks appear in the rules
