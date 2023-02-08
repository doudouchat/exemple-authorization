Feature: password

  Background: 
    Given get access token by client credentials to 'test' and scopes 'ROLE_APP'
    And create username 'jean.dupond@gmail.com' with password 'mdp'

  Scenario: new password
    Given new password for 'jean.dupond@gmail.com'
    And get password token
    When change password 'mdp123' for username 'jean.dupond@gmail.com'
    And get access token by client credentials to 'test' and scopes 'ROLE_APP'
    And login to 'jean.dupond@gmail.com' and password 'mdp123'
    And authorize
      |account|
    And get access token by code
    And account 'jean.dupond@gmail.com' is accessible
