package com.exemple.authorization.resource.login.exception;

import java.text.MessageFormat;

import lombok.Getter;

@Getter
public class UsernameAlreadyExistsException extends RuntimeException {

    protected static final String EXCEPTION_MESSAGE = "Login {0} already exists";

    private final String username;

    public UsernameAlreadyExistsException(String username) {
        super(MessageFormat.format(EXCEPTION_MESSAGE, username));
        this.username = username;
    }

}
