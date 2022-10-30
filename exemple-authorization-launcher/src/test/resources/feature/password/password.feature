Feature: password

  Background: 
    Given get access token by client credentials to 'admin'
    And create username 'jean.dupond@gmail.com' with password 'mdp'

  Scenario: new password
    Given new password for 'jean.dupond@gmail.com'
    And get password token
    When change password 'mdp123' for username 'jean.dupond@gmail.com' by admin
    And connect to 'jean.dupond@gmail.com' and password 'mdp123'
    And account 'jean.dupond@gmail.com' is accessible
