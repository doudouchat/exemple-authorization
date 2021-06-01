package com.exemple.authorization.resource.login.exception;

import java.text.MessageFormat;

public class UsernameAlreadyExistsException extends Exception {

    protected static final String EXCEPTION_MESSAGE = "Login {0} already exists";

    private static final long serialVersionUID = 1L;

    private final String username;

    public UsernameAlreadyExistsException(String username) {
        super(MessageFormat.format(EXCEPTION_MESSAGE, username));
        this.username = username;
    }

    public String getUsername() {
        return this.username;
    }

}
