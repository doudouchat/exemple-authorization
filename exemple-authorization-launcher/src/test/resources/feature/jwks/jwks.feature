Feature: jwks

  Scenario: get jwks
    When get jwks
    Then jwks status is 200
    Then first kid is 'exemple-key-id'
