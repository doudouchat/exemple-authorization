@ignore
Feature: authorization by code implicit

  Background: 
    Given get access token by client credentials to 'test' and scopes 'ROLE_APP'
    And create username 'jean.dupond@gmail.com' with password 'mdp'

  Scenario: authorization by code implicit
    Given login to 'jean.dupond@gmail.com' and password 'mdp'
    When authorize implicit
    Then account 'jean.dupond@gmail.com' is accessible
