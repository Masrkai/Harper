Feature: IP target expansion
  As a user specifying bandwidth targets
  I want host tokens expanded to concrete IPv4 addresses
  So that the shaper knows exactly which clients to limit.

  Scenario: Expanding valid target tokens
    Given the following target tokens
      | token          | count | first        | last         |
      | 192.168.1.5    | 1     | 192.168.1.5  | 192.168.1.5  |
      | 10.0.0.0/30    | 2     | 10.0.0.1     | 10.0.0.2     |
      | 10.0.0.0/29    | 6     | 10.0.0.1     | 10.0.0.6     |
      | 10.0.0.1-3     | 3     | 10.0.0.1     | 10.0.0.3     |
      | 10.0.0.5-5     | 1     | 10.0.0.5     | 10.0.0.5     |
    When each token is expanded with expand_one
    Then the expansion matches the expected count, first, and last address

  Scenario: Rejecting invalid target tokens
    Given the following invalid tokens
      | token       | reason            |
      | not_an_ip   | garbage string    |
      | 10.0.0.5-3  | reversed range    |
      | 999.0.0.1   | invalid octet     |
      | 10.0.0.0/31 | prefix too large  |
      |             | empty string      |
    When each invalid token is expanded
    Then expansion returns an error

  Scenario: Expanding and deduplicating a target list
    Given the raw target list
      | 10.0.0.3 |
      | 10.0.0.1 |
      | 10.0.0.1 |
    When the list is expanded with expand_targets
    Then the result has 2 unique sorted addresses
    And the first address is 10.0.0.1
    And the last address is 10.0.0.3
