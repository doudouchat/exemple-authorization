package com.exemple.authorization.login.model;

import javax.validation.constraints.NotBlank;

import lombok.Builder;
import lombok.Getter;
import lombok.extern.jackson.Jacksonized;

@Builder
@Getter
@Jacksonized
public class CopyLoginModel {

    @NotBlank
    private final String toUsername;

    @NotBlank
    private final String fromUsername;

}
