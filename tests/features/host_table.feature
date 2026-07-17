Feature: Host table lifecycle and lookups
  As the central host registry
  I want correct insertion, removal, state transitions, and lookups
  So that all subsystems (spoofer, forwarder, shaper) see consistent data.

  Scenario: Insert assigns sequential IDs after reindex by IP
    Given IPs and expected IDs
      | ips                       | expected_ids |
      | 10.0.0.3, 10.0.0.1, 10.0.0.2 | 3, 1, 2      |

  Scenario: Duplicate IP updates existing entry
    Given IP and MAC1 and MAC2
      | ip        | mac1            | mac2            |
      | 10.0.0.1  | AA:BB:CC:DD:EE:01 | AA:BB:CC:DD:EE:02 |

  Scenario: Duplicate MAC updates IP of existing entry
    Given IP1 and MAC and IP2
      | ip1       | mac             | ip2       |
      | 10.0.0.1  | AA:BB:CC:DD:EE:01 | 10.0.0.5  |

  Scenario: Remove returns entry and cleans indexes
    Given IP and MAC
      | ip        | mac             |
      | 10.0.0.1  | AA:BB:CC:DD:EE:01 |

  Scenario: Remove missing ID returns None
    Given missing ID
      | missing_id |
      | 999        |

  Scenario: Remove one host does not affect others
    Given IP1 and IP2 and IP3
      | ip1       | ip2       | ip3       |
      | 10.0.0.1  | 10.0.0.2  | 10.0.0.3  |

  Scenario: Initial state of inserted host is Discovered
    Given IP and MAC
      | ip        | mac             |
      | 10.0.0.1  | AA:BB:CC:DD:EE:01 |

  Scenario: Update state cycles through all variants
    Given IP and MAC
      | ip        | mac             |
      | 10.0.0.1  | AA:BB:CC:DD:EE:01 |

  Scenario: Update state on missing ID returns false
    Given missing ID
      | missing_id |
      | 999        |

  Scenario: Get stale with zero max_age returns all hosts
    Given IDs and IPs
      | ids     | ips                 |
      | 1, 2    | 10.0.0.1, 10.0.0.2 |

  Scenario: Get stale with max_age=MAX returns no hosts
    Given IDs and IPs
      | ids     | ips                 |
      | 1, 2    | 10.0.0.1, 10.0.0.2 |

  Scenario: Get stale on empty table returns empty
    Given dummy
      | dummy |
      | x     |

  Scenario: Removed host no longer appears in stale list
    Given IPs and remove ID
      | ips                 | remove_id |
      | 10.0.0.1, 10.0.0.2  | 2         |

  Scenario: Clear empties table and resets ID counter
    Given IPs
      | ips                 |
      | 10.0.0.1, 10.0.0.2  |

  Scenario: Clear empties IP and MAC indexes
    Given IP and MAC
      | ip        | mac             |
      | 10.0.0.1  | AA:BB:CC:DD:EE:01 |

  Scenario: Clear then reinsert works without corruption
    Given IPs
      | ips                 |
      | 10.0.0.1, 10.0.0.2  |

  Scenario: Lookup consistency across all three indexes
    Given IP and MAC
      | ip        | mac             |
      | 10.0.0.77 | AA:BB:CC:DD:EE:77 |

  Scenario: Duplicate IP does not grow table
    Given IP and MAC
      | ip        | mac             |
      | 10.0.0.5  | AA:BB:CC:DD:EE:05 |