package com.exemple.authorization.core.token;

import java.util.Optional;

import org.apache.commons.lang3.NotImplementedException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Token;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;

import com.exemple.authorization.core.token.mapper.OAuth2EntityMapper;
import com.exemple.authorization.resource.oauth2.OAuth2Resource;
import com.exemple.authorization.resource.oauth2.model.OAuth2Entity;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@RequiredArgsConstructor
@Slf4j
public class AuthorizationOAuth2Repository implements OAuth2AuthorizationService {

    private final OAuth2Resource oAuth2Resource;

    private final RegisteredClientRepository registeredClientRepository;

    private final JwtDecoder decoder;

    private final OAuth2EntityMapper mapper;

    @Override
    public void save(OAuth2Authorization authorization) {
        oAuth2Resource.save(mapper.toEntity(authorization));
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        throw new NotImplementedException();
    }

    @Override
    public OAuth2Authorization findById(String id) {
        throw new NotImplementedException();
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {

        if (tokenType != null) {

            Optional<OAuth2Entity> entity = switch (tokenType.getValue()) {
                case OAuth2ParameterNames.CODE -> oAuth2Resource.findByAuthorizationCodeValue(token);
                case OAuth2ParameterNames.REFRESH_TOKEN -> oAuth2Resource.findByRefreshTokenValue(token);
                default -> throw new NotImplementedException();
            };

            return entity.map(mapper::toObject).orElse(null);
        }

        return findByToken(token).orElse(null);

    }

    public Optional<OAuth2Authorization> findByToken(String token) {

        try {
            var jwt = decoder.decode(token);
            return Optional.of(buildOAuth2Authorization(jwt));
        } catch (JwtException e) {
            LOG.debug("token is invalid", e);
            return Optional.empty();
        }
    }

    private OAuth2Authorization buildOAuth2Authorization(Jwt jwt) {

        var builder = OAuth2Authorization
                .withRegisteredClient(registeredClientRepository.findById(jwt.getClaimAsString("client_id")))
                .principalName(jwt.getSubject())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .token(jwt, metadata -> metadata.put(Token.CLAIMS_METADATA_NAME, jwt.getClaims()));

        return builder.build();

    }

}
