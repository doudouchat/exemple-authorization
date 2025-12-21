package com.exemple.authorization.login.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Null;
import lombok.Builder;
import lombok.Getter;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Builder
@Getter
@JsonDeserialize(builder = LoginModel.LoginModelBuilder.class)
public class LoginModel {

    @Null
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private final String username;

    @NotBlank
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private final String password;

    @JsonPOJOBuilder(withPrefix = "")
    public static class LoginModelBuilder {
    }

}
