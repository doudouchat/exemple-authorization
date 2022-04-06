package com.exemple.authorization.login.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public class LoginNotFoundException extends Exception {

    private static final long serialVersionUID = 1L;

    private final String username;

    private final String path;

}
