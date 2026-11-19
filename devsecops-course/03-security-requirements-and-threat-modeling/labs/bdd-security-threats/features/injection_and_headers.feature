@security
Feature: Input handling and hardening
  Background:
    Given a fresh application

  @injection
  Scenario Outline: Injection payloads never reach the database as code (threat T-10)
    When I search for "<payload>"
    Then the response status is not 500
    And the response body does not contain "SQL syntax"

    Examples:
      | payload             |
      | ' OR '1'='1         |
      | "; DROP TABLE users |
      | <script>x</script>  |

  @headers
  Scenario: Hardening headers are present (threat T-04)
    When I request "/"
    Then the response header "X-Content-Type-Options" is "nosniff"
    And the response header "Content-Security-Policy" is present
    And the response header "Server" is absent

  @access
  Scenario: Admin area is not exposed to anonymous users (threat T-06)
    When I request "/admin"
    Then the response status is 404

  @wip
  Scenario: Rate limit on search (not implemented yet, skipped by tag)
    When I request "/search"
    Then the response status is 429
