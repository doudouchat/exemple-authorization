package com.exemple.authorization.password.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

import jakarta.validation.constraints.NotBlank;
import lombok.Builder;
import lombok.Getter;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Builder
@Getter
@JsonDeserialize(builder = NewPassword.NewPasswordBuilder.class)
public class NewPassword {

    @NotBlank
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String login;

    @JsonPOJOBuilder(withPrefix = "")
    public static class NewPasswordBuilder {
    }
}
