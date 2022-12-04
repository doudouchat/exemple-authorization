@ignore
Feature: authorization by password

  Background: 
    Given get access token by client credentials to 'test' and scopes 'ROLE_APP'
    And create username 'jean.dupond@gmail.com' with password 'mdp'

  Scenario: authorization by password
    When get access token by password for username 'jean.dupond@gmail.com' and password 'mdp'
    Then account 'jean.dupond@gmail.com' is accessible
    And refresh access token

  Scenario: authorization by password for back
    When get access token by password for back 'admin' and password 'admin123'
    Then back is accessible

  Scenario: authorization by password unauthorized
    Then get access token by password for username 'jean.dupond@gmail.com' and password 'mdp123' is unauthorized

  Scenario: authorization by password forbidden
    When get access token by password for username 'jean.dupond@gmail.com' and password 'mdp'
    Then account 'jean.dupont@gmail.com' is forbidden

  Scenario: authorization by password bad request
    Given create disable username 'jean.dupont@gmail.com' with password 'mdp'
    Then get access token by password for username 'jean.dupont@gmail.com' and password 'mdp' is bad
