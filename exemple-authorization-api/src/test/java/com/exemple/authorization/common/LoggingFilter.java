package com.exemple.authorization.common;

import java.io.OutputStream;
import java.io.PrintStream;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;

import io.restassured.filter.Filter;
import io.restassured.filter.FilterContext;
import io.restassured.filter.log.LogDetail;
import io.restassured.internal.print.RequestPrinter;
import io.restassured.internal.print.ResponsePrinter;
import io.restassured.response.Response;
import io.restassured.specification.FilterableRequestSpecification;
import io.restassured.specification.FilterableResponseSpecification;

public class LoggingFilter implements Filter {

    private final Logger log;

    private static final AtomicInteger COUNTER;

    static {

        COUNTER = new AtomicInteger();
    }

    public LoggingFilter(Logger log) {
        this.log = log;
    }

    @Override
    public Response filter(FilterableRequestSpecification requestSpec, FilterableResponseSpecification responseSpec, FilterContext ctx) {

        int counter = COUNTER.incrementAndGet();

        String requestLog = RequestPrinter.print(requestSpec, requestSpec.getMethod(), requestSpec.getURI(), LogDetail.ALL, Collections.emptySet(),
                new PrintStream(OutputStream.nullOutputStream()), true);
        this.log.debug("Request {}\n{}", counter, requestLog);

        Response response = ctx.next(requestSpec, responseSpec);

        String responseLog = ResponsePrinter.print(response, response,
                new PrintStream(OutputStream.nullOutputStream()),
                LogDetail.ALL, true, Collections.emptySet());
        this.log.debug("Response {}\n{}", counter, responseLog);

        return response;
    }

}
