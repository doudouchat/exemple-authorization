package com.exemple.authorization.resource.core.cassandra;

import java.nio.ByteBuffer;

import com.datastax.oss.driver.api.core.ProtocolVersion;
import com.datastax.oss.driver.api.core.type.DataType;
import com.datastax.oss.driver.api.core.type.DataTypes;
import com.datastax.oss.driver.api.core.type.codec.TypeCodec;
import com.datastax.oss.driver.api.core.type.reflect.GenericType;
import com.datastax.oss.driver.internal.core.util.Strings;
import com.datastax.oss.protocol.internal.util.Bytes;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

public class Json3Codec implements TypeCodec<JsonNode> {

    private final ObjectMapper objectMapper;
    private final GenericType<JsonNode> type;

    public Json3Codec() {
        this.objectMapper = new ObjectMapper();
        this.type = GenericType.of(JsonNode.class);
    }

    @Override
    public GenericType<JsonNode> getJavaType() {
        return type;
    }

    @Override
    public DataType getCqlType() {
        return DataTypes.TEXT;
    }

    @Override
    public ByteBuffer encode(JsonNode value, ProtocolVersion protocolVersion) {
        if (value == null) {
            return null;
        }
        return ByteBuffer.wrap(objectMapper.writeValueAsBytes(value));
    }

    @Override
    public JsonNode decode(ByteBuffer bytes, ProtocolVersion protocolVersion) {
        if (bytes == null) {
            return null;
        }
        return objectMapper.readValue(Bytes.getArray(bytes), JsonNode.class);
    }

    @Override
    public String format(JsonNode value) {
        return Strings.quote(objectMapper.writeValueAsString(value));
    }

    @Override
    public JsonNode parse(String value) {
        return objectMapper.readValue(value, JsonNode.class);
    }

}
