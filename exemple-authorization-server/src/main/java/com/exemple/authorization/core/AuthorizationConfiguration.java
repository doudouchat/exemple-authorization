package com.exemple.authorization.core;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestValidator;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenStore;

import com.exemple.authorization.core.authentication.account.AccountDetailsService;
import com.exemple.authorization.core.client.AuthorizationClientBuilder;
import com.exemple.authorization.core.resource.keyspace.AuthorizationResourceKeyspace;

@Configuration
@EnableAuthorizationServer
public class AuthorizationConfiguration extends AuthorizationServerConfigurerAdapter {

    private final AuthenticationManager authenticationManager;

    private final TokenStore tokenStore;

    private final TokenEnhancer tokenEnhancer;

    private final AuthorizationClientBuilder authorizationClientBuilder;

    private final AuthorizationResourceKeyspace authorizationResourceKeyspace;

    private final AccountDetailsService accountDetailsService;

    public AuthorizationConfiguration(AuthenticationManager authenticationManager, TokenStore tokenStore, TokenEnhancer tokenEnhancer,
            AuthorizationClientBuilder authorizationClientBuilder, AuthorizationResourceKeyspace authorizationResourceKeyspace,
            AccountDetailsService accountDetailsService) {

        this.authenticationManager = authenticationManager;
        this.tokenStore = tokenStore;
        this.tokenEnhancer = tokenEnhancer;
        this.authorizationClientBuilder = authorizationClientBuilder;
        this.authorizationResourceKeyspace = authorizationResourceKeyspace;
        this.accountDetailsService = accountDetailsService;
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {

        endpoints.tokenStore(tokenStore).userDetailsService(accountDetailsService).tokenEnhancer(tokenEnhancer)
                .authenticationManager(authenticationManager).requestValidator(new DefaultOAuth2RequestValidator() {

                    @Override
                    public void validateScope(TokenRequest tokenRequest, ClientDetails client) {

                        super.validateScope(tokenRequest, client);

                        authorizationResourceKeyspace.initKeyspace(client);
                    }
                });
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
        oauthServer.tokenKeyAccess("hasRole('ROLE_TRUSTED_CLIENT')").checkTokenAccess("hasRole('ROLE_TRUSTED_CLIENT')");
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {

        clients.setBuilder(this.authorizationClientBuilder);

    }

}
