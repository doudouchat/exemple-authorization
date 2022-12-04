package com.exemple.authorization.core.authentication;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.exemple.authorization.application.detail.ApplicationDetailService;
import com.exemple.authorization.core.authentication.provider.AccountAuthenticationProvider;
import com.exemple.authorization.core.authentication.provider.BackAuthenticationProvider;
import com.exemple.authorization.resource.core.ResourceExecutionContext;

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
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

        http
                .antMatcher("/login")
                .addFilterBefore(new BearerTokenAuthenticationFilter(authenticationManager()), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new InitKeyspaceFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilter(new UsernamePasswordAuthenticationFilter(authenticationManager()))
                .authorizeHttpRequests()
                .anyRequest().authenticated().and()
                .csrf(csrf -> csrf.ignoringRequestMatchers(new AntPathRequestMatcher("/login")));

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
