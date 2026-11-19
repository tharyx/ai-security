@session
Feature: Session management
  Threat: an attacker steals or guesses a session and acts as the user.
  Requirement (ASVS-style, simplified): session cookies are protected and unpredictable.

  Background:
    Given the application is running

  Scenario: Session cookie must be HttpOnly
    When I log in as "alice" with password "correct-horse"
    Then the response sets a cookie named "session"
    And the cookie "session" has the "HttpOnly" flag

  Scenario: Session cookie must be sent over HTTPS only
    When I log in as "alice" with password "correct-horse"
    Then the cookie "session" has the "Secure" flag
    And the cookie "session" has SameSite "Lax" or "Strict"

  Scenario: Session identifiers are unpredictable
    When I log in as "alice" with password "correct-horse" in two separate sessions
    Then the two session ids are different and at least 32 characters long

  Scenario: Logout invalidates the session on the server
    When I log in as "alice" with password "correct-horse"
    And I log out
    And I request "/admin" with the old session
    Then the response status is 302 or 401
