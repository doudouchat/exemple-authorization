package com.exemple.authorization.login;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;

import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Component;

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
import jakarta.annotation.security.RolesAllowed;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.HEAD;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;
import jakarta.ws.rs.core.SecurityContext;
import jakarta.ws.rs.core.UriInfo;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
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
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/{username}")
    @Operation(tags = "login")
    @RolesAllowed("login:head")
    public void check(@NotBlank @PathParam("username") String username) {

        if (loginResource.get(username).isEmpty()) {

            throw new NotFoundException();
        }

    }

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("/{username}")
    @Operation(tags = "login")
    @ApiResponses(value = {

            @ApiResponse(description = "Login is updated", responseCode = "204"),
            @ApiResponse(description = "Login is not found", responseCode = "404"),
            @ApiResponse(description = "Login is not accessible", responseCode = "403")

    })
    @RolesAllowed({ "login:create", "login:update" })
    public Response update(@PathParam("username") String username, @Valid @NotNull LoginModel source, @Context UriInfo uriInfo) {

        Optional<LoginEntity> origin = loginResource.get(username);

        Response response;

        if (origin.isPresent()) {

            checkIfUsernameHasRight(username, servletContext.getSecurityContext());

            var entity = toLoginEntity(source, origin.get());
            entity.setUsername(username);
            entity.setPassword(encryptPassword(entity.getPassword()));

            loginResource.update(entity);

            response = Response.noContent().build();

        } else {

            var entity = toLoginEntity(source);
            entity.setUsername(username);
            entity.setPassword(encryptPassword(entity.getPassword()));

            loginResource.save(entity);

            var builder = uriInfo.getBaseUriBuilder();
            builder.path("v1/logins/" + username);
            response = Response.created(builder.build()).build();

        }

        return response;

    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("/move")
    @Operation(tags = "login")
    @ApiResponses(value = {

            @ApiResponse(description = "Login is created", responseCode = "201"),
            @ApiResponse(description = "Login is not found", responseCode = "404"),
            @ApiResponse(description = "Login is not accessible", responseCode = "403")

    })
    @RolesAllowed({ "login:create", "login:update" })
    public Response copy(@Valid @NotNull CopyLoginModel copy, @Context UriInfo uriInfo) throws LoginNotFoundException {

        checkIfUsernameHasRight(copy.getFromUsername(), servletContext.getSecurityContext());

        LoginEntity origin = loginResource.get(copy.getFromUsername())
                .orElseThrow(() -> new LoginNotFoundException(copy.getFromUsername(), "/fromUsername"));

        origin.setUsername(copy.getToUsername());

        loginResource.save(origin);
        loginResource.delete(copy.getFromUsername());

        var builder = uriInfo.getBaseUriBuilder();
        builder.path("v1/logins/" + copy.getToUsername());

        return Response.created(builder.build()).build();

    }

    @Provider
    public static class UsernameAlreadyExistsExceptionMapper implements ExceptionMapper<UsernameAlreadyExistsException> {

        @Override
        public Response toResponse(UsernameAlreadyExistsException exception) {

            Map<String, Object> cause = Map.of(
                    "code", "username",
                    "message", "[".concat(exception.getUsername()).concat("] already exists"));

            return Response.status(Status.BAD_REQUEST).type(MediaType.APPLICATION_JSON).entity(Collections.singletonList(cause)).build();

        }

    }

    @Provider
    public static class LoginNotFoundExceptionMapper implements ExceptionMapper<LoginNotFoundException> {

        @Override
        public Response toResponse(LoginNotFoundException exception) {

            Map<String, Object> cause = Map.of(
                    "path", exception.getPath(),
                    "code", "not_found",
                    "message", "[".concat(exception.getUsername()).concat("] not found"));

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

    private static LoginEntity toLoginEntity(LoginModel resource, LoginEntity loginEntity) {

        var entity = new LoginEntity();

        entity.setAccountLocked(loginEntity.isAccountLocked());
        entity.setDisabled(loginEntity.isDisabled());
        entity.setPassword(resource.getPassword());
        entity.setUsername(resource.getUsername());

        return entity;

    }

}
