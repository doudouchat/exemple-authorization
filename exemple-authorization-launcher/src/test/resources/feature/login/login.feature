Feature: login

  Background: 
    Given get access token by client credentials to 'test' and scopes 'login:update login:head'
    And delete username 'jean.dupond@gmail.com'
    And delete username 'jean.dupont@gmail.com'

  Scenario: new login
    When new username 'jean.dupond@gmail.com' with password 'mdp'
    Then username 'jean.dupond@gmail.com' exists
    And get access token by client credentials to 'test' and scopes 'ROLE_APP'
    And login to 'jean.dupond@gmail.com' and password 'mdp'
    And authorize
      |login:head|
    And get access token by code
    And account 'jean.dupond@gmail.com' is accessible

  Scenario: disconnection
    Given create username 'jean.dupond@gmail.com' with password 'mdp'
    And get access token by client credentials to 'test' and scopes 'ROLE_APP'
    And login to 'jean.dupond@gmail.com' and password 'mdp'
    And authorize
      |login:head|
    And get access token by code
    And account 'jean.dupond@gmail.com' is accessible
    When disconnection
    Then account 'jean.dupond@gmail.com' is unauthorized

  Scenario: change username
    Given create username 'jean.dupond@gmail.com' with password 'mdp'
    And get access token by client credentials to 'test' and scopes 'ROLE_APP'
    And login to 'jean.dupond@gmail.com' and password 'mdp'
    And authorize
      |login:update|login:head|
    And get access token by code
    When change username from 'jean.dupond@gmail.com' to 'jean.dupont@gmail.com'
    And username 'jean.dupont@gmail.com' exists
    And get access token by client credentials to 'test' and scopes 'ROLE_APP'
    And login to 'jean.dupont@gmail.com' and password 'mdp'
    And authorize
      |login:head|
    And get access token by code
    And account 'jean.dupont@gmail.com' is accessible

  Scenario: change username fails because username alreday exists
    Given create username 'jean.dupont@gmail.com' with password 'mdp'
    And create username 'jean.dupond@gmail.com' with password 'mdp'
    And get access token by client credentials to 'test' and scopes 'ROLE_APP'
    And login to 'jean.dupond@gmail.com' and password 'mdp'
    And authorize
      |login:update|
    And get access token by code
    When change username from 'jean.dupond@gmail.com' to 'jean.dupont@gmail.com' fails because
      """
      [
				{"code":"username","path":"/toUsername","message":"[jean.dupont@gmail.com] already exists"}
      ]
      """
