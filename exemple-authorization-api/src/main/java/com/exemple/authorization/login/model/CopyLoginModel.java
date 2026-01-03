package com.exemple.authorization.login.model;

import jakarta.validation.constraints.NotBlank;
import lombok.Builder;
import lombok.Getter;
import tools.jackson.databind.annotation.JsonDeserialize;
import tools.jackson.databind.annotation.JsonPOJOBuilder;

@Builder
@Getter
//TODO move to @Jacksonized
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
