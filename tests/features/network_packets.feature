Feature: ARP packet builders and parser
  As the ARP spoofing engine
  I want correct Ethernet+ARP frame construction
  So that victims and gateway update their caches with our MAC.

  Scenario: ARP request frame has correct fields
    Given a target IP, sender IP, and sender MAC
      | target_ip    | sender_ip    | sender_mac        |
      | 192.168.1.10 | 192.168.1.100 | AA:BB:CC:DD:EE:FF |
    When an ArpRequest is built for the target
    Then the Ethernet destination is broadcast
    And the Ethernet source is the sender MAC
    And the EtherType is ARP (0x0806)
    And the ARP operation is Request (1)
    And the ARP sender hardware address is the sender MAC
    And the ARP sender protocol address is the sender IP
    And the ARP target protocol address is the target IP
    And the ARP target hardware address is zero

  Scenario: ARP poison victim direction lies about gateway MAC
    Given a victim MAC, victim IP, gateway IP, and our MAC
      | victim_mac       | victim_ip    | gateway_ip   | our_mac        |
      | 11:22:33:44:55:66 | 192.168.1.10 | 192.168.1.1  | AA:BB:CC:DD:EE:FF |
    When an ArpPoison is built for the victim
    Then the Ethernet destination is the victim MAC
    And the Ethernet source is our MAC
    And the ARP operation is Reply (2)
    And the ARP sender hardware address is our MAC
    And the ARP sender protocol address is the gateway IP
    And the ARP target hardware address is the victim MAC
    And the ARP target protocol address is the victim IP

  Scenario: ARP poison gateway direction lies about victim MAC
    Given a gateway MAC, gateway IP, victim IP, and our MAC
      | gateway_mac      | gateway_ip   | victim_ip    | our_mac        |
      | DE:AD:BE:EF:00:01 | 192.168.1.1  | 192.168.1.10 | AA:BB:CC:DD:EE:FF |
    When an ArpPoison is built for the gateway
    Then the Ethernet destination is the gateway MAC
    And the Ethernet source is our MAC
    And the ARP operation is Reply (2)
    And the ARP sender hardware address is our MAC
    And the ARP sender protocol address is the victim IP
    And the ARP target hardware address is the gateway MAC
    And the ARP target protocol address is the gateway IP

  Scenario: ARP restore tells victim the true gateway MAC
    Given a victim MAC, victim IP, real gateway IP, and real gateway MAC
      | victim_mac       | victim_ip    | real_gateway_ip | real_gateway_mac |
      | 11:22:33:44:55:66 | 192.168.1.10 | 192.168.1.1     | DE:AD:BE:EF:00:01 |
    When an ArpRestore is built for the victim
    Then the Ethernet destination is the victim MAC
    And the Ethernet source is the real gateway MAC
    And the ARP operation is Reply (2)
    And the ARP sender hardware address is the real gateway MAC
    And the ARP sender protocol address is the real gateway IP
    And the ARP target hardware address is the victim MAC
    And the ARP target protocol address is the victim IP

  Scenario: ARP reply parser accepts poison frames
    Given a victim MAC, victim IP, gateway IP, and our MAC
      | victim_mac       | victim_ip    | gateway_ip   | our_mac        |
      | 11:22:33:44:55:66 | 192.168.1.10 | 192.168.1.1  | AA:BB:CC:DD:EE:FF |
    When ArpReply::from_bytes is called with the ArpPoison frame
    Then the result is Some
    And the sender MAC matches the frame's sender MAC
    And the sender IP matches the frame's sender IP
    And the target MAC matches the frame's target MAC
    And the target IP matches the frame's target IP

  Scenario: ARP reply parser accepts restore frames
    Given a victim MAC, victim IP, real gateway IP, and real gateway MAC
      | victim_mac       | victim_ip    | real_gateway_ip | real_gateway_mac |
      | 11:22:33:44:55:66 | 192.168.1.10 | 192.168.1.1     | DE:AD:BE:EF:00:01 |
    When ArpReply::from_bytes is called with the ArpRestore frame
    Then the result is Some
    And the sender MAC is the real gateway MAC
    And the sender IP is the real gateway IP

  Scenario: ARP reply parser rejects ARP request frames
    Given a target IP, sender IP, and sender MAC
      | target_ip    | sender_ip    | sender_mac        |
      | 192.168.1.10 | 192.168.1.100 | AA:BB:CC:DD:EE:FF |
    When ArpReply::from_bytes is called with the ArpRequest frame
    Then the result is None

  Scenario: ARP reply parser rejects short buffers
    Given a buffer length
      | length |
      | 20     |
    When ArpReply::from_bytes is called with a buffer of that length
    Then the result is None

  Scenario: ARP reply parser rejects all-zero buffer
    Given a 42-byte all-zero buffer
      | dummy |
      | x     |
    When ArpReply::from_bytes is called with the buffer
    Then the result is None

  Scenario: ARP reply parser rejects empty buffer
    Given an empty buffer
      | dummy |
      | x     |
    When ArpReply::from_bytes is called with the buffer
    Then the result is None

  Scenario: All builders produce exactly 42-byte frames
    Given a victim MAC, victim IP, gateway IP, and our MAC
      | victim_mac       | victim_ip    | gateway_ip   | our_mac        |
      | 11:22:33:44:55:66 | 192.168.1.10 | 192.168.1.1  | AA:BB:CC:DD:EE:FF |
    When each builder's to_bytes() is called
    Then every frame length is 42