package com.exemple.authorization.integration;

import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;

@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
@Configuration
public class TestSecurityConfiguration {

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

        http
                .authorizeHttpRequests().requestMatchers("/actuator/**").permitAll()
                .anyRequest().authenticated().and()
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::opaqueToken);

        return http.build();

    }

    @Bean
    public OpaqueTokenIntrospector introspector(
            @Value("${spring.security.oauth2.resourceserver.opaque-token.introspection-uri}") String introspectionUri,
            @Value("${spring.security.oauth2.resourceserver.opaque-token.client-id}") String clientId,
            @Value("${spring.security.oauth2.resourceserver.opaque-token.client-secret}") String clientSecret) {
        return new CustomAuthoritiesOpaqueTokenIntrospector(introspectionUri, clientId, clientSecret);
    }

    private static class CustomAuthoritiesOpaqueTokenIntrospector implements OpaqueTokenIntrospector {
        private final OpaqueTokenIntrospector delegate;

        public CustomAuthoritiesOpaqueTokenIntrospector(String introspectionUri, String clientId, String clientSecret) {
            delegate = new NimbusOpaqueTokenIntrospector(introspectionUri, clientId, clientSecret);
        }

        public OAuth2AuthenticatedPrincipal introspect(String token) {
            OAuth2AuthenticatedPrincipal principal = this.delegate.introspect(token);
            return new DefaultOAuth2AuthenticatedPrincipal(principal.getName(), principal.getAttributes(), extractAuthorities(principal));
        }

        private static Collection<GrantedAuthority> extractAuthorities(OAuth2AuthenticatedPrincipal principal) {

            List<?> scopes = principal.getAttribute(OAuth2TokenIntrospectionClaimNames.SCOPE);
            List<?> authorities = principal.getAttribute("authorities");

            assert scopes != null;
            assert authorities != null;

            return Stream.concat(scopes.stream(), authorities.stream())
                    .map(String.class::cast)
                    .map(SimpleGrantedAuthority::new)
                    .map(GrantedAuthority.class::cast)
                    .toList();
        }
    }
}
