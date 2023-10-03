package com.exemple.authorization.password.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties(prefix = "authorization.password")
public record PasswordProperties(@DefaultValue("86400") long expiryTime) {

}
