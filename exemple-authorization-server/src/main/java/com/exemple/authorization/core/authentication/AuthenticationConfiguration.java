package com.exemple.authorization.core.authentication;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;

import com.exemple.authorization.core.authentication.filter.AuthenticationFilter;
import com.exemple.authorization.core.authentication.provider.AccountAuthenticationProvider;
import com.exemple.authorization.core.authentication.provider.BackAuthenticationProvider;
import com.exemple.authorization.core.resource.keyspace.AuthorizationResourceKeyspace;

import lombok.RequiredArgsConstructor;

@Configuration
@ComponentScan(basePackages = "com.exemple.authorization.core.authentication", basePackageClasses = AuthorizationResourceKeyspace.class)
@RequiredArgsConstructor
public class AuthenticationConfiguration extends WebSecurityConfigurerAdapter {

    private final DefaultTokenServices tokenServices;

    private final AccountAuthenticationProvider accountAuthenticationProvider;

    private final BackAuthenticationProvider backAuthenticationProvider;

    private final AuthorizationResourceKeyspace authorizationResourceKeyspace;

    @Autowired
    public void globalUserDetails(final AuthenticationManagerBuilder auth) {

        auth.eraseCredentials(false).authenticationProvider(accountAuthenticationProvider).authenticationProvider(backAuthenticationProvider)
                .authenticationProvider(new AuthenticationProvider() {

                    @Override
                    public Authentication authenticate(Authentication authentication) {
                        throw new AuthenticationServiceException("Bad Credentials");
                    }

                    @Override
                    public boolean supports(Class<?> authentication) {
                        return true;
                    }

                });
    }

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    public void configure(WebSecurity web) {

        web.ignoring().antMatchers(HttpMethod.OPTIONS, "/oauth/token");
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {

        var filter = new AuthenticationFilter(tokenServices, authorizationResourceKeyspace, "ROLE_APP");
        filter.setAuthenticationManager(authenticationManagerBean());

        http
                .requestMatchers()
                .antMatchers("/login", "/oauth/**").and()
                .addFilter(filter)
                .authorizeRequests()
                .anyRequest().authenticated().and().csrf().disable();

    }
}
