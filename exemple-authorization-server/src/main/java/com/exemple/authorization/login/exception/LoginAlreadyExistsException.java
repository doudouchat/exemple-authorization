package com.exemple.authorization.login.exception;

import com.exemple.authorization.resource.login.exception.UsernameAlreadyExistsException;

import lombok.Getter;

@Getter
public class LoginAlreadyExistsException extends UsernameAlreadyExistsException {

    private static final long serialVersionUID = 1L;

    private final String path;

    public LoginAlreadyExistsException(String username, String path) {
        super(username);
        this.path = path;
    }

}
