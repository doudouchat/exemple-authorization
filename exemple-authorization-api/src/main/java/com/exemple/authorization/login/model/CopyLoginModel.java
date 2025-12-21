package com.exemple.authorization.login.model;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

import jakarta.validation.constraints.NotBlank;
import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
@JsonDeserialize(builder = CopyLoginModel.CopyLoginModelBuilder.class)
public class CopyLoginModel {

    @NotBlank
    private final String toUsername;

    @NotBlank
    private final String fromUsername;

    @JsonPOJOBuilder(withPrefix = "")
    public static class CopyLoginModelBuilder {
    }

}
