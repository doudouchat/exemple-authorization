package com.exemple.authorization.core;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.exemple.authorization.core.client.AuthorizationClientRepository;
import com.exemple.authorization.core.jwk.AuthorizationJwkConfiguration;
import com.exemple.authorization.core.token.AuthorizationOAuth2Repository;
import com.exemple.authorization.core.token.provider.RevokeTokenProvider;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import lombok.RequiredArgsConstructor;

@Configuration
@Import({ AuthorizationJwkConfiguration.class, AuthorizationClientRepository.class })
@ComponentScan(basePackageClasses = AuthorizationOAuth2Repository.class)
@RequiredArgsConstructor
public class AuthorizationConfiguration {

    private final JWKSource<SecurityContext> jwkSource;

    private final RevokeTokenProvider revokeTokenProvider;

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        var authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

        authorizationServerConfigurer.tokenRevocationEndpoint(tokenRevocationEndpoint -> tokenRevocationEndpoint
                .authenticationProviders((List<AuthenticationProvider> providers) -> {
                    providers.clear();
                    providers.add(revokeTokenProvider);
                }));

        http
                .securityMatcher(endpointsMatcher)
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(new AntPathRequestMatcher("/**")).permitAll())
                .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
                .with(authorizationServerConfigurer, Customizer.withDefaults());

        return http.build();
    }

    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(
            RegisteredClientRepository registeredClientRepository) {
        return new InMemoryOAuth2AuthorizationConsentService();
    }

    @Bean
    public OAuth2TokenGenerator<OAuth2Token> tokenGenerator() {
        var jwtEncoder = new NimbusJwtEncoder(jwkSource);
        var jwtGenerator = new JwtGenerator(jwtEncoder);
        jwtGenerator.setJwtCustomizer(jwtCustomizer());
        var refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
        return new DelegatingOAuth2TokenGenerator(jwtGenerator, refreshTokenGenerator);
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return (JwtEncodingContext context) -> {
            JwtClaimsSet.Builder claims = context.getClaims();
            if (context.getAuthorization() != null) {
                claims.id(context.getAuthorization().getId());
            }
            claims.claim("client_id", context.getRegisteredClient().getClientId());
            claims.claim("authorities", context.getPrincipal().getAuthorities().stream()
                    .map(GrantedAuthority.class::cast)
                    .map(GrantedAuthority::getAuthority)
                    .toList());
        };
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .authorizationEndpoint("/oauth/authorize")
                .tokenEndpoint("/oauth/token")
                .tokenIntrospectionEndpoint("/oauth/check_token")
                .jwkSetEndpoint("/oauth/jwks")
                .tokenRevocationEndpoint("/oauth/revoke_token")
                .build();
    }
}
