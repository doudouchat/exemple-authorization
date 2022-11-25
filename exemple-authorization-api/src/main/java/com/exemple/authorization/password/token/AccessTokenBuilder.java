package com.exemple.authorization.password.token;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;

import javax.validation.Valid;

import org.apache.commons.lang3.ObjectUtils;
import org.springframework.stereotype.Component;

import com.exemple.authorization.application.common.exception.NotFoundApplicationException;
import com.exemple.authorization.application.detail.ApplicationDetailService;
import com.exemple.authorization.common.security.AuthorizationContextSecurity;
import com.exemple.authorization.password.model.NewPassword;
import com.exemple.authorization.password.properties.PasswordProperties;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;

@Component
@RequiredArgsConstructor
public class AccessTokenBuilder {

    private final JWSSigner algorithm;

    private final ApplicationDetailService applicationDetailService;

    private final PasswordProperties passwordProperties;

    private final Clock clock;

    @SneakyThrows
    public String createAccessToken(@Valid NewPassword newPassword, String app, AuthorizationContextSecurity securityContext) {

        var applicationDetail = applicationDetailService.get(app).orElseThrow(() -> new NotFoundApplicationException(app));

        var expiresAt = Date.from(Instant.now(clock)
                .plus(ObjectUtils.defaultIfNull(applicationDetail.getExpiryTimePassword(), passwordProperties.getExpiryTime()),
                        ChronoUnit.SECONDS));

        var payload = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .claim("scope", new String[] { "login:update", "login:read" })
                .subject(newPassword.getLogin())
                .expirationTime(expiresAt)
                .claim("client_id", securityContext.getJwt().getClaimAsString("client_id"))
                .claim("authorities", securityContext.getRoles().toArray(String[]::new))
                .build();

        var token = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).build(), payload);
        token.sign(algorithm);

        return token.serialize();

    }

}
