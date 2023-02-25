package com.exemple.authorization.resource.oauth2;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.util.Optional;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import com.exemple.authorization.resource.core.ResourceExecutionContext;
import com.exemple.authorization.resource.core.ResourceTestConfiguration;
import com.exemple.authorization.resource.oauth2.model.OAuth2Entity;

@SpringBootTest(classes = ResourceTestConfiguration.class)
@ActiveProfiles("test")
class OAuth2ResourceTest {

    @Autowired
    private OAuth2Resource resource;

    @BeforeAll
    static void initKeyspace() {

        ResourceExecutionContext.get().setKeyspace("main");

    }

    @AfterAll
    static void destroy() {

        ResourceExecutionContext.destroy();

    }

    @Test
    void save() {

        // Given oauth2 token

        String authorizationCodeToken = "authorization code token";
        String refreshToken = "refresh token";

        OAuth2Entity oauth2Entity = new OAuth2Entity();
        oauth2Entity.setId("1");
        oauth2Entity.setAuthorizationCodeValue(authorizationCodeToken);
        oauth2Entity.setRefreshTokenValue(refreshToken);

        // When perform

        resource.save(oauth2Entity);

        // Then check oauth2 token

        Optional<OAuth2Entity> actualOAuth2 = resource.findById("1");
        assertAll(
                () -> assertThat(actualOAuth2).isNotEmpty(),
                () -> assertThat(actualOAuth2).hasValueSatisfying(
                        oauth2 -> assertAll(
                                () -> assertThat(oauth2.getId()).isEqualTo("1"),
                                () -> assertThat(oauth2.getAuthorizationCodeValue()).isEqualTo(authorizationCodeToken),
                                () -> assertThat(oauth2.getRefreshTokenValue()).isEqualTo(refreshToken))));
    }

    @Test
    void findByAuthorizationCodeValue() {

        // Given oauth2 token

        String authorizationCodeToken = "authorization code token";

        OAuth2Entity oauth2Entity = new OAuth2Entity();
        oauth2Entity.setId("1");
        oauth2Entity.setAuthorizationCodeValue(authorizationCodeToken);

        // When perform

        resource.save(oauth2Entity);

        // Then check oauth2 token

        Optional<OAuth2Entity> actualOAuth2 = resource.findByAuthorizationCodeValue(authorizationCodeToken);
        assertAll(
                () -> assertThat(actualOAuth2).isNotEmpty(),
                () -> assertThat(actualOAuth2).hasValueSatisfying(
                        oauth2 -> assertAll(
                                () -> assertThat(oauth2.getId()).isEqualTo("1"),
                                () -> assertThat(oauth2.getAuthorizationCodeValue()).isEqualTo(authorizationCodeToken))));
    }

    @Test
    void findByRefreshTokenValue() {

        // Given oauth2 token

        String refreshToken = "refresh token";

        OAuth2Entity oauth2Entity = new OAuth2Entity();
        oauth2Entity.setId("1");
        oauth2Entity.setRefreshTokenValue(refreshToken);

        // When perform

        resource.save(oauth2Entity);

        // Then check oauth2 token

        Optional<OAuth2Entity> actualOAuth2 = resource.findByRefreshTokenValue(refreshToken);
        assertAll(
                () -> assertThat(actualOAuth2).isNotEmpty(),
                () -> assertThat(actualOAuth2).hasValueSatisfying(
                        oauth2 -> assertAll(
                                () -> assertThat(oauth2.getId()).isEqualTo("1"),
                                () -> assertThat(oauth2.getRefreshTokenValue()).isEqualTo(refreshToken))));
    }

}
