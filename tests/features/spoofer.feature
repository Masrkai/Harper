Feature: Spoofer ARP poison direction
  As the MITM operator
  I want each victim's ARP cache poisoned with the correct lies
  So that traffic between victim and gateway flows through me.

  Scenario: Victim-direction poison claims the gateway IP is at our MAC
    Given a spoof target for victim 192.168.1.5 (AA:BB:CC:00:00:02)
      And gateway 192.168.1.1 (AA:BB:CC:00:00:01)
      And our MAC is AA:BB:CC:00:00:FF
    When the victim-direction poison frame is built
    Then the frame targets the victim MAC AA:BB:CC:00:00:02
    And the frame claims the gateway IP 192.168.1.1 is at our MAC AA:BB:CC:00:00:FF

  Scenario: Gateway-direction poison claims the victim IP is at our MAC
    Given a spoof target for victim 192.168.1.5 (AA:BB:CC:00:00:02)
      And gateway 192.168.1.1 (AA:BB:CC:00:00:01)
      And our MAC is AA:BB:CC:00:00:FF
    When the gateway-direction poison frame is built
    Then the frame targets the gateway MAC AA:BB:CC:00:00:01
    And the frame claims the victim IP 192.168.1.5 is at our MAC AA:BB:CC:00:00:FF

   Scenario: Restore-on-stop tells the victim the true gateway MAC
     Given a spoof target for victim 192.168.1.5 (AA:BB:CC:00:00:02)
       And gateway 192.168.1.1 (AA:BB:CC:00:00:01)
     When the victim-direction restore frame is built
     Then the frame targets the victim MAC AA:BB:CC:00:00:02
     And the frame claims the gateway IP 192.168.1.1 is at the true gateway MAC AA:BB:CC:00:00:01

   Scenario: Spoofer applies distinct phase offsets per victim IP
     Given two victims with different IPs 192.168.1.5 and 192.168.1.6
     When phase offsets are computed for both victims
     Then their phase offsets are distinct

