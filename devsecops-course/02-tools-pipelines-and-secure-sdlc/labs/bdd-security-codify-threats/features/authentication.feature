@authentication
Feature: Login protection
  Threat: online password guessing and user enumeration.

  Background:
    Given the application is running

  Scenario: Login must lock after 5 failures
    When I fail to log in as "alice" 5 times in a row
    And I log in as "alice" with password "correct-horse"
    Then the response status is 423

  Scenario: Four failures do not lock the account yet
    When I fail to log in as "alice" 4 times in a row
    And I log in as "alice" with password "correct-horse"
    Then the response status is 200

  Scenario: Error message must not reveal whether the user exists
    When I log in as "nobody-here" with password "x"
    And I remember the response body
    And I log in as "alice" with password "wrong-password"
    Then the response body is the same as the remembered body

  Scenario Outline: Admin area is closed to everyone but admins
    When I log in as "<user>" with password "<password>"
    And I request "/admin" with my session
    Then the response status is <status>

    Examples:
      | user       | password       | status |
      | alice      | correct-horse  | 403    |
      | root-admin | battery-staple | 200    |

  Scenario: Anonymous users are sent to the login page
    When I request "/admin" anonymously
    Then the response status is 302
    And the response header "Location" contains "/login"
