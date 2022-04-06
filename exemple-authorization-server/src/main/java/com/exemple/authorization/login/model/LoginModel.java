package com.exemple.authorization.login.model;

import java.util.Set;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Null;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Builder;
import lombok.Getter;
import lombok.Singular;
import lombok.extern.jackson.Jacksonized;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Builder
@Getter
@Jacksonized
public class LoginModel {

    @Null
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private final String username;

    @NotBlank
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private final String password;

    private final boolean disabled;

    private final boolean accountLocked;

    @Singular
    private final Set<String> roles;

}
