package com.exemple.authorization.application.common.exception;

import lombok.Getter;

@Getter
public class NotFoundApplicationException extends RuntimeException {

    private final String application;

    public NotFoundApplicationException(String application, Throwable e) {
        super(e);
        this.application = application;
    }

}
