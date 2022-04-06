package com.exemple.authorization.core.token;

import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.nimbusds.jose.jwk.JWKSet;

import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
public class JwkSetApi {

    private final JWKSet jwkSet;

    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> publicKeys() {
        return this.jwkSet.toJSONObject();
    }

}
