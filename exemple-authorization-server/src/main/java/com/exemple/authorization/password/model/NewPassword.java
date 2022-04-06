package com.exemple.authorization.password.model;

import javax.validation.constraints.NotBlank;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Builder;
import lombok.Getter;
import lombok.extern.jackson.Jacksonized;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Builder
@Getter
@Jacksonized
public class NewPassword {

    @NotBlank
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String login;

}
