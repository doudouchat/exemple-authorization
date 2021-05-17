package com.exemple.authorization.login.exception;

public class LoginNotFoundException extends Exception {

    private static final long serialVersionUID = 1L;

    private final String username;

    private final String path;

    public LoginNotFoundException(String username, String path) {
        this.username = username;
        this.path = path;
    }

    public String getUsername() {
        return this.username;
    }

    public String getPath() {
        return path;
    }

}
