Feature: actuate

  Scenario: info
    When get info
    Then actuate status is 200
    And actuate property 'version' exists
    And actuate property 'buildTime' exists
