package com.exemple.authorization.password.token;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;

import org.apache.commons.lang3.ObjectUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.exemple.authorization.application.common.model.ApplicationDetail;
import com.exemple.authorization.application.detail.ApplicationDetailService;
import com.exemple.authorization.common.security.AuthorizationContextSecurity;
import com.exemple.authorization.password.model.NewPassword;
import com.exemple.authorization.password.properties.PasswordProperties;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class AccessTokenBuilder {

    private final Algorithm algorithm;

    private final ApplicationDetailService applicationDetailService;

    private final PasswordProperties passwordProperties;

    private final Clock clock;

    public String createAccessToken(NewPassword newPassword, String app, AuthorizationContextSecurity securityContext) {

        ApplicationDetail applicationDetail = applicationDetailService.get(app);

        Date expiresAt = Date.from(Instant.now(clock)
                .plus(ObjectUtils.defaultIfNull(applicationDetail.getExpiryTimePassword(), passwordProperties.getExpiryTime()), ChronoUnit.SECONDS));

        return JWT.create()

                .withJWTId(UUID.randomUUID().toString())

                .withArrayClaim("scope", new String[] { "login:update", "login:read" })

                .withSubject(newPassword.getLogin()).withExpiresAt(expiresAt)

                .withClaim("client_id", securityContext.getAuthentication().getOAuth2Request().getClientId())

                .withArrayClaim("authorities",
                        securityContext.getAuthentication().getOAuth2Request().getAuthorities().stream().map(GrantedAuthority::getAuthority)
                                .toArray(String[]::new))

                .sign(algorithm);

    }

}
