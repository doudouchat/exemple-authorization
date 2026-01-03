package com.exemple.authorization.resource.core.cassandra;

import java.nio.ByteBuffer;

import com.datastax.oss.driver.api.core.ProtocolVersion;
import com.datastax.oss.driver.internal.core.type.codec.extras.json.JsonCodec;
import com.datastax.oss.protocol.internal.util.Bytes;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * @deprecated should use any JsonCode from datastax
 */
@Deprecated(forRemoval = true)
public class Json3Codec extends JsonCodec<JsonNode> {

    private final ObjectMapper objectMapper;

    public Json3Codec() {
        super(JsonNode.class);
        this.objectMapper = new ObjectMapper();
    }

    @Override
    public ByteBuffer encode(JsonNode value, ProtocolVersion protocolVersion) {
        return ByteBuffer.wrap(objectMapper.writeValueAsBytes(value));
    }

    @Override
    public JsonNode decode(ByteBuffer bytes, ProtocolVersion protocolVersion) {
        if (bytes == null) {
            return null;
        }
        return objectMapper.readValue(Bytes.getArray(bytes), JsonNode.class);
    }

}
