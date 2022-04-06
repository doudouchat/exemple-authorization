
package com.exemple.authorization.resource.login.model;

import java.util.Collections;
import java.util.Set;

import com.datastax.oss.driver.api.mapper.annotations.CqlName;
import com.datastax.oss.driver.api.mapper.annotations.Entity;
import com.datastax.oss.driver.api.mapper.annotations.PartitionKey;

import lombok.Getter;
import lombok.Setter;

@Entity
@CqlName("login")
@Getter
@Setter
public class LoginEntity {

    @PartitionKey
    private String username;

    private String password;

    private boolean disabled;

    private boolean accountLocked;

    private Set<String> roles = Collections.emptySet();

}
