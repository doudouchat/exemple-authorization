package com.exemple.authorization.resource.login;

import java.util.Optional;

import com.exemple.authorization.resource.login.exception.UsernameAlreadyExistsException;
import com.exemple.authorization.resource.login.model.LoginEntity;

public interface LoginResource {

    Optional<LoginEntity> get(String username);

    void update(LoginEntity login);

    void save(LoginEntity login) throws UsernameAlreadyExistsException;

    void delete(String username);

}
