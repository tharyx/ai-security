@headers
Feature: Security headers and information exposure
  Threat: clickjacking, MIME sniffing, and reconnaissance from banners and forgotten files.

  Background:
    Given the application is running

  Scenario Outline: Responses carry the required security headers
    When I request "/" anonymously
    Then the response header "<header>" contains "<value>"

    Examples:
      | header                    | value          |
      | Strict-Transport-Security | max-age        |
      | X-Content-Type-Options    | nosniff        |
      | X-Frame-Options           | DENY           |
      | Content-Security-Policy   | default-src    |

  Scenario: The server must not advertise its software version
    When I request "/" anonymously
    Then the response header "Server" does not reveal a version number
    And the response header "X-Powered-By" is absent

  Scenario Outline: Version control and backup files are not served
    When I request "<path>" anonymously
    Then the response status is 404

    Examples:
      | path        |
      | /.git/config |
      | /.git/HEAD   |
