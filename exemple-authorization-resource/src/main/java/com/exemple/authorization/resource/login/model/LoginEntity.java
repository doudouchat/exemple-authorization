
package com.exemple.authorization.resource.login.model;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import com.datastax.oss.driver.api.mapper.annotations.CqlName;
import com.datastax.oss.driver.api.mapper.annotations.Entity;
import com.datastax.oss.driver.api.mapper.annotations.PartitionKey;

@Entity
@CqlName("login")
public class LoginEntity {

    @PartitionKey
    private String username;

    private String password;

    private boolean disabled;

    private boolean accountLocked;

    private Set<String> roles = Collections.emptySet();

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public boolean isDisabled() {
        return disabled;
    }

    public void setDisabled(boolean disabled) {
        this.disabled = disabled;
    }

    public boolean isAccountLocked() {
        return accountLocked;
    }

    public void setAccountLocked(boolean accountLocked) {
        this.accountLocked = accountLocked;
    }

    public Set<String> getRoles() {
        return new HashSet<>(roles);
    }

    public void setRoles(Set<String> roles) {
        this.roles = new HashSet<>(roles);
    }

}
