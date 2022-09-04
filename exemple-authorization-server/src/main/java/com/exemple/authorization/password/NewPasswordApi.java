package com.exemple.authorization.password;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import javax.annotation.security.RolesAllowed;
import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.ws.rs.Consumes;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.KafkaHeaders;
import org.springframework.messaging.Message;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.stereotype.Component;

import com.exemple.authorization.common.security.AuthorizationContextSecurity;
import com.exemple.authorization.core.feature.FeatureConfiguration;
import com.exemple.authorization.password.model.NewPassword;
import com.exemple.authorization.password.token.AccessTokenBuilder;
import com.exemple.authorization.resource.login.LoginResource;
import com.exemple.authorization.resource.login.model.LoginEntity;

import lombok.RequiredArgsConstructor;

@Path("/v1/new_password")
@Component
@RequiredArgsConstructor
public class NewPasswordApi {

    @Context
    private ContainerRequestContext servletContext;

    private final LoginResource loginResource;

    private final KafkaTemplate<String, Map<String, Object>> template;

    private final AccessTokenBuilder accessTokenBuilder;

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @RolesAllowed({ "ROLE_APP", "ROLE_TRUSTED_CLIENT" })
    public Response post(@NotNull @Valid NewPassword newPassword, @NotBlank @HeaderParam(FeatureConfiguration.APP_HEADER) String app) {

        AuthorizationContextSecurity securityContext = (AuthorizationContextSecurity) servletContext.getSecurityContext();

        Optional<String> accessToken = loginResource.get(newPassword.getLogin())
                .map((LoginEntity login) -> accessTokenBuilder.createAccessToken(newPassword, app, securityContext));

        if (securityContext.isUserInRole("ROLE_TRUSTED_CLIENT")) {

            Map<String, Object> data = new HashMap<>();
            accessToken.ifPresent(token -> data.put("token", token));
            return Response.status(Status.OK).entity(data).build();

        }

        accessToken.ifPresent((String token) -> {
            Map<String, Object> data = Map.of(
                    "token", token);
            Message<Map<String, Object>> message = MessageBuilder.withPayload(data).setHeader(KafkaHeaders.TOPIC, "new_password").build();
            template.send(message);
        });

        return Response.status(Status.NO_CONTENT).build();

    }

}
