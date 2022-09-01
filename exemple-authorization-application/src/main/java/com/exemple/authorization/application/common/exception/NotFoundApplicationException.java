package com.exemple.authorization.application.common.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public class NotFoundApplicationException extends RuntimeException {

    private final String application;

}
