package com.exemple.authorization.application.common.exception;

public class NotFoundApplicationException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final String application;

    public NotFoundApplicationException(String application, Throwable e) {
        super(e);
        this.application = application;
    }

    public String getApplication() {
        return application;
    }

}
