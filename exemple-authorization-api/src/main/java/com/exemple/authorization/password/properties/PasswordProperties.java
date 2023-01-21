package com.exemple.authorization.password.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import lombok.Getter;

@ConfigurationProperties(prefix = "authorization.password")
@Getter
public class PasswordProperties {

    private final long expiryTime;

    public PasswordProperties(@DefaultValue("86400") long expiryTime) {
        this.expiryTime = expiryTime;
    }

}
