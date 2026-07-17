Feature: Target selection parsing for CLI
  As a user selecting bandwidth targets
  I want flexible input formats (single, range, comma-list, "all")
  So that I can shape exactly the clients I intend.

  Scenario: Single valid ID selects that host
    Given available host IDs and selection string and expected result
      | available        | input | expected |
      | 1,2,3,4,5        | 3     | 3        |

  Scenario: Inclusive range selects all IDs in range
    Given available host IDs and selection string and expected result
      | available        | input | expected |
      | 1,2,3,4,5        | 2-4   | 2,3,4    |

  Scenario: Range skips unavailable IDs
    Given available host IDs and selection string and expected result
      | available        | input | expected |
      | 1,3,5            | 1-5   | 1,3,5    |

  Scenario: Comma-separated list selects multiple IDs
    Given available host IDs and selection string and expected result
      | available        | input | expected |
      | 1,2,3,4,5        | 1,3,5 | 1,3,5    |

  Scenario: Comma list with spaces is accepted
    Given available host IDs and selection string and expected result
      | available        | input   | expected |
      | 1,2,3,4,5        | 1, 3, 5 | 1,3,5    |

  Scenario: Comma list deduplicates and sorts output
    Given available host IDs and selection string and expected result
      | available        | input   | expected |
      | 1,2,3,4,5        | 5,1,3,1 | 1,3,5    |

  Scenario: Mixed range and comma list works
    Given available host IDs and selection string and expected result
      | available        | input | expected |
      | 1,2,3,4,5        | 1-3,5 | 1,2,3,5  |

  Scenario: Overlapping range and single deduplicates
    Given available host IDs and selection string and expected result
      | available        | input | expected |
      | 1,2,3,4,5        | 1-3,2 | 1,2,3    |

  Scenario: "all" keyword returns all available IDs (lowercase)
    Given available host IDs and selection string and expected result
      | available | input | expected |
      | 2,4       | all   | 2,4      |

  Scenario: "all" keyword is case-insensitive
    Given available host IDs and selection string and expected result
      | available | input | expected |
      | 2,4       | ALL   | 2,4      |

  Scenario: "all" with empty available returns empty list
    Given available host IDs and selection string and expected result
      | available | input | expected |
      | 99        | all   | 99       |

  Scenario: Invalid ID outside available set is rejected
    Given available host IDs and selection string
      | available | input |
      | 1,2       | 5     |
    When parse_selection is called
    Then the result is None

  Scenario: Zero ID is rejected
    Given available host IDs and selection string
      | available | input |
      | 1,2,3     | 0     |
    When parse_selection is called
    Then the result is None

  Scenario: Negative ID is rejected
    Given available host IDs and selection string
      | available | input |
      | 1,2,3     | -1    |
    When parse_selection is called
    Then the result is None

  Scenario: Reversed range (start > end) is rejected
    Given available host IDs and selection string
      | available | input |
      | 1,2,3,4,5 | 5-2   |
    When parse_selection is called
    Then the result is None

  Scenario: Range end above maximum is rejected
    Given available host IDs and selection string
      | available | input |
      | 1,2,3,4,5 | 3-99  |
    When parse_selection is called
    Then the result is None

  Scenario: Non-numeric token is rejected
    Given available host IDs and selection string
      | available | input |
      | 1,2,3     | abc   |
    When parse_selection is called
    Then the result is None

  Scenario: Float token is rejected
    Given available host IDs and selection string
      | available | input |
      | 1,2,3     | 1.5   |
    When parse_selection is called
    Then the result is None

  Scenario: Empty string returns rejected
    Given available host IDs and selection string
      | available | input |
      | 1,2,3     |       |
    When parse_selection is called
    Then the result is None

  Scenario: Trailing comma skips empty token
    Given available host IDs and selection string and expected result
      | available | input | expected |
      | 1,2,3     | 1,    | 1        |

  Scenario: Comma-only does not panic
    Given available host IDs and selection string
      | available | input |
      | 1,2,3     | ,     |
    When parse_selection is called
    Then the result is None

  Scenario: Bandwidth parsing - empty string means unlimited
    Given bandwidth input and expected result
      | input | expected |
      |       | unlimited |

  Scenario: Bandwidth parsing - zero means unlimited
    Given bandwidth input and expected result
      | input | expected |
      | 0     | unlimited |

  Scenario: Bandwidth parsing - positive integer returns Some(kbps)
    Given bandwidth input and expected result
      | input     | expected |
      | 512       | 512      |

  Scenario: Bandwidth parsing - large integer returns Some(kbps)
    Given bandwidth input and expected result
      | input      | expected |
      | 1000000    | 1000000  |

  Scenario: Bandwidth parsing - negative returns unlimited
    Given bandwidth input and expected result
      | input  | expected |
      | -100   | unlimited |

  Scenario: Bandwidth parsing - non-numeric returns unlimited
    Given bandwidth input and expected result
      | input | expected |
      | abc   | unlimited |

  Scenario: Bandwidth parsing - float returns unlimited
    Given bandwidth input and expected result
      | input | expected |
      | 1.5   | unlimited |