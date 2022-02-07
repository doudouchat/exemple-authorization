package com.exemple.authorization.integration;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@RestController
public class TestApi {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @GetMapping("/account/{id}")
    @Secured("ROLE_ACCOUNT")
    public JsonNode get(@PathVariable String id) {

        return MAPPER.createObjectNode();

    }

    @GetMapping("/back/{id}")
    @Secured("ROLE_BACK")
    public JsonNode get(@PathVariable Integer id) {

        return MAPPER.createObjectNode();

    }

    @PostMapping("/account")
    @PreAuthorize("hasAuthority('login:update')")
    public void post() {

    }
}
