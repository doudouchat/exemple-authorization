package com.exemple.authorization.password.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.validation.constraints.NotBlank;
import lombok.Builder;
import lombok.Getter;
import tools.jackson.databind.annotation.JsonDeserialize;
import tools.jackson.databind.annotation.JsonPOJOBuilder;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Builder
@Getter
//TODO move to @Jacksonized
@JsonDeserialize(builder = NewPassword.NewPasswordBuilder.class)
public class NewPassword {

    @NotBlank
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String login;

    @JsonPOJOBuilder(withPrefix = "")
    public static class NewPasswordBuilder {
    }
}
