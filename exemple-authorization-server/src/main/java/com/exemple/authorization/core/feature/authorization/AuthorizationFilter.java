package com.exemple.authorization.core.feature.authorization;

import java.util.regex.Pattern;

import javax.annotation.Priority;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Response;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;

import com.auth0.jwt.JWT;
import com.exemple.authorization.application.common.model.ApplicationDetail;
import com.exemple.authorization.application.detail.ApplicationDetailService;
import com.exemple.authorization.common.security.AuthorizationContextSecurity;
import com.exemple.authorization.core.feature.FeatureConfiguration;
import com.exemple.authorization.core.resource.keyspace.AuthorizationResourceKeyspace;

@Priority(Priorities.AUTHENTICATION)
public class AuthorizationFilter implements ContainerRequestFilter {

    private static final Pattern BEARER;

    static {

        BEARER = Pattern.compile("Bearer ");
    }

    @Autowired
    private DefaultTokenServices tokenServices;

    @Autowired
    private AuthorizationResourceKeyspace authorizationResourceKeyspace;

    @Autowired
    private ApplicationDetailService applicationDetailService;

    @Override
    public void filter(ContainerRequestContext requestContext) {

        if (StringUtils.startsWith(requestContext.getHeaderString("Authorization"), "Bearer ")) {

            try {

                String accessToken = BEARER.matcher(requestContext.getHeaderString("Authorization")).replaceFirst("");

                OAuth2Authentication authentication = tokenServices.loadAuthentication(accessToken);

                requestContext.setSecurityContext(new AuthorizationContextSecurity(authentication, JWT.decode(accessToken)));

                ApplicationDetail applicationDetail = applicationDetailService.get(requestContext.getHeaderString(FeatureConfiguration.APP_HEADER));

                if (!applicationDetail.getClientIds().contains(authentication.getOAuth2Request().getClientId())) {
                    throw new InvalidTokenException(authentication.getOAuth2Request().getClientId() + " is forbidden");
                }

                authorizationResourceKeyspace.initKeyspace(applicationDetail.getKeyspace());

            } catch (InvalidTokenException e) {

                requestContext.abortWith(build(e));
            }
        }

    }

    private static Response build(InvalidTokenException e) {

        return Response.status(Response.Status.FORBIDDEN).entity(e.getMessage()).build();
    }

}
