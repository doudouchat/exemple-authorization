package com.exemple.authorization.login.model;

import javax.validation.constraints.NotBlank;

public class CopyLoginModel {

    @NotBlank
    private String toUsername;

    @NotBlank
    private String fromUsername;

    public String getToUsername() {
        return toUsername;
    }

    public void setToUsername(String toUsername) {
        this.toUsername = toUsername;
    }

    public String getFromUsername() {
        return fromUsername;
    }

    public void setFromUsername(String fromUsername) {
        this.fromUsername = fromUsername;
    }

}
