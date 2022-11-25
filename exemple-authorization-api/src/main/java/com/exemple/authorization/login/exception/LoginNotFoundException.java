package com.exemple.authorization.login.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public class LoginNotFoundException extends Exception {

    private final String username;

    private final String path;

}
