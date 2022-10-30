Feature: swagger

  Scenario: get swagger
    When get swagger schema
    Then schema status is 200
