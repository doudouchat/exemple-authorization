package com.exemple.authorization.resource.login;

import java.util.Optional;

import com.exemple.authorization.resource.login.model.LoginEntity;

public interface LoginResource {

    Optional<LoginEntity> get(String login);

}
