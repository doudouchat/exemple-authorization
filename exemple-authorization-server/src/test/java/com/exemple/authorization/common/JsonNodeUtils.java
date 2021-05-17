package com.exemple.authorization.common;

import java.util.function.Supplier;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public final class JsonNodeUtils {

    private JsonNodeUtils() {

    }

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static JsonNode create(Supplier<?> source) {

        return MAPPER.convertValue(source.get(), JsonNode.class);

    }

}
