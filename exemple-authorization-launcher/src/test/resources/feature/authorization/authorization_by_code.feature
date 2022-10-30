Feature: authorization by code

  Background: 
    Given get access token by client credentials to 'test'
    And create username 'jean.dupond@gmail.com' with password 'mdp'

  Scenario: authorization by code
    Given login to 'jean.dupond@gmail.com' and password 'mdp'
    And authorize
      |account|
    When get access token by code
    Then account 'jean.dupond@gmail.com' is accessible
    And refresh access token

  Scenario: authorization by code unauthorized
    Then login to 'jean.dupond@gmail.com' and password 'mdp123' is unauthorized

  Scenario: authorization by code forbidden
    Given login to 'jean.dupond@gmail.com' and password 'mdp'
    And authorize
      |account|
    When get access token by code
    Then account 'jean.dupont@gmail.com' is forbidden

  Scenario: authorization by code bad request
    Given create disable username 'jean.dupont@gmail.com' with password 'mdp'
    Then login to 'jean.dupont@gmail.com' and password 'mdp' is bad
