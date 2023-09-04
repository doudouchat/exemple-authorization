package com.exemple.authorization.integration;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.parameters.P;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@RestController
public class TestApi {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @GetMapping("/account/{id}")
    @PreAuthorize("hasRole('ROLE_ACCOUNT') and #id == authentication.principal.name")
    public JsonNode get(@P("id") @PathVariable("id") String id) {

        return MAPPER.createObjectNode();

    }

    @GetMapping("/back/{id}")
    @Secured("ROLE_BACK")
    public JsonNode get(@PathVariable("id") Integer id) {

        return MAPPER.createObjectNode();

    }
}
