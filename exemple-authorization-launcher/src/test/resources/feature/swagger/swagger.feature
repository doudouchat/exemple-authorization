Feature: swagger

  Scenario: get swagger
    When get swagger schema
    Then schema status is 200
    #And schema contains paths
    #| /ExempleAuthorization/oauth/authorize | /ExempleAuthorization/oauth/check_token | /ExempleAuthorization/oauth/token | /ExempleAuthorization/oauth/token_key | /ExempleAuthorization/oauth/confirm_access | /ExempleAuthorization/oauth/error |