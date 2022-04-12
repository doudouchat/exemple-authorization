package com.exemple.authorization.login;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import javax.annotation.security.RolesAllowed;
import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.ws.rs.ForbiddenException;
import javax.ws.rs.HEAD;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.core.SecurityContext;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.stereotype.Component;

import com.exemple.authorization.login.exception.LoginAlreadyExistsException;
import com.exemple.authorization.login.exception.LoginNotFoundException;
import com.exemple.authorization.login.model.CopyLoginModel;
import com.exemple.authorization.login.model.LoginModel;
import com.exemple.authorization.resource.login.LoginResource;
import com.exemple.authorization.resource.login.exception.UsernameAlreadyExistsException;
import com.exemple.authorization.resource.login.model.LoginEntity;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;

@Path("/v1/logins")
@OpenAPIDefinition(tags = @Tag(name = "login"))
@Component
@RequiredArgsConstructor
public class LoginApi {

    private final LoginResource loginResource;

    @Context
    private ContainerRequestContext servletContext;

    @HEAD
    @Path("/{username}")
    @Operation(tags = "login")
    @RolesAllowed("login:head")
    public Response check(@NotBlank @PathParam("username") String username) {

        if (loginResource.get(username).isPresent()) {

            return Response.status(Status.NO_CONTENT).build();
        }

        return Response.status(Status.NOT_FOUND).build();

    }

    @PUT
    @Path("/{username}")
    @Operation(tags = "login")
    @ApiResponses(value = {

            @ApiResponse(description = "Login is updated", responseCode = "204"),
            @ApiResponse(description = "Login is not found", responseCode = "404"),
            @ApiResponse(description = "Login is not accessible", responseCode = "403")

    })
    @RolesAllowed({ "login:create", "login:update" })
    public Response update(@PathParam("username") String username, @Valid @NotNull LoginModel source, @Context UriInfo uriInfo)
            throws UsernameAlreadyExistsException {

        Optional<LoginEntity> origin = loginResource.get(username);

        Response response;

        if (origin.isPresent()) {

            checkIfUsernameHasRight(username, servletContext.getSecurityContext());

            LoginEntity entity = toLoginEntity(source, origin.get());
            entity.setUsername(username);
            entity.setPassword(encryptPassword(entity.getPassword()));

            loginResource.update(entity);

            response = Response.status(Status.NO_CONTENT).build();

        } else {

            LoginEntity entity = toLoginEntity(source);
            entity.setUsername(username);
            entity.setPassword(encryptPassword(entity.getPassword()));

            loginResource.save(entity);

            UriBuilder builder = uriInfo.getBaseUriBuilder();
            builder.path("v1/logins/" + username);
            response = Response.created(builder.build()).build();

        }

        return response;

    }

    @POST
    @Path("/move")
    @Operation(tags = "login")
    @ApiResponses(value = {

            @ApiResponse(description = "Login is created", responseCode = "201"),
            @ApiResponse(description = "Login is not found", responseCode = "404"),
            @ApiResponse(description = "Login is not accessible", responseCode = "403")

    })
    @RolesAllowed({ "login:create", "login:update" })
    public Response copy(@Valid @NotNull CopyLoginModel copy, @Context UriInfo uriInfo) throws LoginNotFoundException, LoginAlreadyExistsException {

        checkIfUsernameHasRight(copy.getFromUsername(), servletContext.getSecurityContext());

        LoginEntity origin = loginResource.get(copy.getFromUsername())
                .orElseThrow(() -> new LoginNotFoundException(copy.getFromUsername(), "/fromUsername"));

        origin.setUsername(copy.getToUsername());

        try {
            loginResource.save(origin);
        } catch (UsernameAlreadyExistsException e) {
            throw new LoginAlreadyExistsException(e.getUsername(), "/toUsername");
        }

        loginResource.delete(copy.getFromUsername());

        UriBuilder builder = uriInfo.getBaseUriBuilder();
        builder.path("v1/logins/" + copy.getToUsername());

        return Response.created(builder.build()).build();

    }

    @Provider
    public static class UsernameAlreadyExistsExceptionMapper implements ExceptionMapper<UsernameAlreadyExistsException> {

        @Override
        public Response toResponse(UsernameAlreadyExistsException exception) {

            Map<String, Object> cause = new HashMap<>();
            cause.put("path", "/username");
            cause.put("code", "username");
            cause.put("message", "[".concat(exception.getUsername()).concat("] already exists"));

            return Response.status(Status.BAD_REQUEST).type(MediaType.APPLICATION_JSON).entity(Collections.singletonList(cause)).build();

        }

    }

    @Provider
    public static class LoginAlreadyExistsExceptionMapper implements ExceptionMapper<LoginAlreadyExistsException> {

        @Override
        public Response toResponse(LoginAlreadyExistsException exception) {

            Map<String, Object> cause = new HashMap<>();
            cause.put("path", exception.getPath());
            cause.put("code", "username");
            cause.put("message", "[".concat(exception.getUsername()).concat("] already exists"));

            return Response.status(Status.BAD_REQUEST).type(MediaType.APPLICATION_JSON).entity(Collections.singletonList(cause)).build();

        }

    }

    @Provider
    public static class LoginNotFoundExceptionMapper implements ExceptionMapper<LoginNotFoundException> {

        @Override
        public Response toResponse(LoginNotFoundException exception) {

            Map<String, Object> cause = new HashMap<>();
            cause.put("path", exception.getPath());
            cause.put("code", "not_found");
            cause.put("message", "[".concat(exception.getUsername()).concat("] not found"));

            return Response.status(Status.BAD_REQUEST).type(MediaType.APPLICATION_JSON).entity(Collections.singletonList(cause)).build();

        }

    }

    private static void checkIfUsernameHasRight(String username, SecurityContext securityContext) {

        if (!username.equals(securityContext.getUserPrincipal().getName())) {

            throw new ForbiddenException();
        }
    }

    private static String encryptPassword(String password) {

        return "{bcrypt}" + BCrypt.hashpw(password, BCrypt.gensalt());

    }

    private static LoginEntity toLoginEntity(LoginModel resource) {

        return toLoginEntity(resource, new LoginEntity());

    }

    private static LoginEntity toLoginEntity(LoginModel resource, LoginEntity entity) {

        entity.setPassword(resource.getPassword());
        entity.setUsername(resource.getUsername());

        return entity;

    }

}
