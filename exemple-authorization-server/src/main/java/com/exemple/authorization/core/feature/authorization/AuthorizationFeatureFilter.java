package com.exemple.authorization.core.feature.authorization;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.regex.Pattern;

import javax.annotation.Priority;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;

import org.apache.commons.lang3.ObjectUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimAccessor;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.util.Assert;

import com.exemple.authorization.application.common.exception.NotFoundApplicationException;
import com.exemple.authorization.application.detail.ApplicationDetailService;
import com.exemple.authorization.common.security.AuthorizationContextSecurity;
import com.exemple.authorization.core.feature.FeatureConfiguration;
import com.exemple.authorization.core.resource.keyspace.AuthorizationResourceKeyspace;

@Priority(Priorities.AUTHENTICATION)
public class AuthorizationFeatureFilter implements ContainerRequestFilter {

    private static final Pattern BEARER;

    static {

        BEARER = Pattern.compile("Bearer (.*)");
    }

    @Autowired
    private AuthorizationResourceKeyspace authorizationResourceKeyspace;

    @Autowired
    private ApplicationDetailService applicationDetailService;

    @Autowired
    private JwtDecoder jwtDecoder;

    @Override
    public void filter(ContainerRequestContext requestContext) {

        String token = requestContext.getHeaders().getFirst("Authorization");

        if (token != null) {

            var jwt = jwtDecoder.decode(extractAccessToken(BEARER, token));

            requestContext.setSecurityContext(buildApiSecurityContext(jwt));

            var applicationName = requestContext.getHeaderString(FeatureConfiguration.APP_HEADER);
            var applicationDetail = applicationDetailService.get(applicationName)
                    .orElseThrow(() -> new NotFoundApplicationException(applicationName));

            if (!applicationDetail.getClientIds().contains(getClientId(jwt))) {

                throw new NotFoundApplicationException(getClientId(jwt));
            }

            authorizationResourceKeyspace.initKeyspace(applicationDetail.getKeyspace());

        }

    }

    private static AuthorizationContextSecurity buildApiSecurityContext(Jwt jwt) {

        Principal principal = () -> ObjectUtils.defaultIfNull(jwt.getSubject(), getClientId(jwt));
        Collection<String> roles = new ArrayList<>();
        if (jwt.hasClaim("scope")) {
            roles.addAll(jwt.getClaimAsStringList("scope"));
        }
        if (jwt.hasClaim("authorities")) {
            roles.addAll(jwt.getClaimAsStringList("authorities"));
        }
        return new AuthorizationContextSecurity(principal, roles, jwt);
    }

    private static String getClientId(JwtClaimAccessor jwt) {

        return jwt.getClaimAsString("client_id");
    }

    private static String extractAccessToken(Pattern pattern, String authorization) {

        var matcher = pattern.matcher(authorization);

        Assert.isTrue(matcher.lookingAt(), "Pattern is invalid");

        return matcher.group(1);

    }

}
