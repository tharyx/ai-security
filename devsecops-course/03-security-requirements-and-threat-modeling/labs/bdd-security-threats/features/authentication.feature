@security @authentication
Feature: Login protection
  As the security team we codify the threats from the threat model as executable specs.

  Background:
    Given a fresh application

  @critical
  Scenario: Account locks after repeated failures (threat T-01 credential guessing)
    When I submit a wrong password 5 times for "alice"
    And I log in as "alice" with password "correct-horse-battery"
    Then the response status is 429

  Scenario: Unknown users and wrong passwords look the same (threat T-09 user enumeration)
    When I log in as "nobody" with password "x"
    Then the response body does not contain "no such user"
    And the response status is 401

  Scenario: Session cookie has protective flags (threat T-02 session theft)
    When I log in as "bob" with password "tr0ub4dor-and-3"
    Then the response status is 200
    And the cookie "sid" has the flags "Secure, HttpOnly, SameSite"
