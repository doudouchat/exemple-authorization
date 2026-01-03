package com.exemple.authorization.core.authentication;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.session.hazelcast.HazelcastIndexedSessionRepository;
import org.springframework.session.security.SpringSessionBackedSessionRegistry;

import com.exemple.authorization.application.detail.ApplicationDetailService;
import com.exemple.authorization.core.authentication.provider.AccountAuthenticationProvider;
import com.exemple.authorization.core.authentication.provider.BackAuthenticationProvider;
import com.exemple.authorization.resource.core.ResourceExecutionContext;
import com.hazelcast.core.HazelcastInstance;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

@Configuration
@ComponentScan(basePackages = "com.exemple.authorization.core.authentication")
@RequiredArgsConstructor
public class AuthenticationConfiguration {

    public static final String APP_HEADER = "app";

    private final AccountAuthenticationProvider accountAuthenticationProvider;

    private final BackAuthenticationProvider backAuthenticationProvider;

    private final JwtDecoder decoder;

    private final ApplicationDetailService applicationDetailService;

    @Bean
    public AuthenticationManager authenticationManager() {

        return new ProviderManager(new JwtAuthenticationProvider(decoder), accountAuthenticationProvider, backAuthenticationProvider);

    }

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http,
            @Qualifier("hazelcastSession") HazelcastInstance sessionHazelcastInstance) {

        var sessionStrategy = new RegisterSessionAuthenticationStrategy(
                new SpringSessionBackedSessionRegistry<>(new HazelcastIndexedSessionRepository(sessionHazelcastInstance)));

        var filter = new UsernamePasswordAuthenticationFilter();
        filter.setAuthenticationManager(authenticationManager());
        filter.setSessionAuthenticationStrategy(sessionStrategy);
        filter.setSecurityContextRepository(new HttpSessionSecurityContextRepository());

        http
                .securityMatcher("/login")
                .addFilterBefore(new BearerTokenAuthenticationFilter(authenticationManager()), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new InitKeyspaceFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilter(filter)
                .csrf(csrf -> csrf.ignoringRequestMatchers(PathPatternRequestMatcher.withDefaults().matcher("/login")));

        return http.build();

    }

    class InitKeyspaceFilter implements Filter {

        @Override
        public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

            var httpRequest = (HttpServletRequest) request;
            var applicationName = httpRequest.getHeader(APP_HEADER);
            if (applicationName != null) {
                applicationDetailService.get(applicationName)
                        .ifPresent(applicationDetail -> ResourceExecutionContext.get().setKeyspace(applicationDetail.getKeyspace()));
            }

            chain.doFilter(request, response);

        }
    }
}
