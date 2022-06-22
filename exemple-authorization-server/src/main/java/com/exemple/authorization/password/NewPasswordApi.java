package com.exemple.authorization.password;

import java.util.Collections;
import java.util.Map;

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

        if (!securityContext.isUserInRole("ROLE_TRUSTED_CLIENT")) {

            if (loginResource.get(newPassword.getLogin()).isPresent()) {
                String accessToken = accessTokenBuilder.createAccessToken(newPassword, app, securityContext);
                Message<Map<String, String>> message = MessageBuilder.withPayload(Collections.singletonMap("token", accessToken))
                        .setHeader(KafkaHeaders.TOPIC, "new_password").build();
                template.send(message);
            }

            return Response.status(Status.NO_CONTENT).build();
        }

        String accessToken = accessTokenBuilder.createAccessToken(newPassword, app, securityContext);
        return Response.status(Status.OK).entity(Collections.singletonMap("token", accessToken)).build();

    }

}
