package com.exemple.authorization.core.authentication.filter;

import java.util.Arrays;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.BearerTokenExtractor;
import org.springframework.security.oauth2.provider.authentication.TokenExtractor;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.exemple.authorization.core.resource.keyspace.AuthorizationResourceKeyspace;

public class AuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final DefaultTokenServices tokenServices;
    private final AuthorizationResourceKeyspace authorizationResourceKeyspace;
    private final TokenExtractor tokenExtractor;
    private final List<String> authorities;

    public AuthenticationFilter(DefaultTokenServices tokenServices, AuthorizationResourceKeyspace authorizationResourceKeyspace,
            String... authorities) {

        this.tokenServices = tokenServices;
        this.authorizationResourceKeyspace = authorizationResourceKeyspace;
        this.tokenExtractor = new BearerTokenExtractor();
        this.authorities = Arrays.asList(authorities);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {

        var preAuthentication = tokenExtractor.extract(request);

        if (preAuthentication != null) {

            OAuth2Authentication authentication;

            try {

                authentication = tokenServices.loadAuthentication((String) preAuthentication.getPrincipal());

            } catch (InvalidTokenException e) {

                throw new AuthenticationServiceException("Token is incorrect", e);
            }

            if (authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).noneMatch(this.authorities::contains)) {

                throw new InsufficientAuthenticationException("Token has not authority to access to logging");
            }

            SecurityContextHolder.getContext().setAuthentication(authentication);

            authorizationResourceKeyspace.initKeyspace(authentication.getOAuth2Request());

            return super.attemptAuthentication(request, response);

        }

        throw new AuthenticationCredentialsNotFoundException("Token is not found");
    }

}
