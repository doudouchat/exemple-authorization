package com.exemple.authorization.password.properties;

import java.time.temporal.ChronoUnit;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "authorization.password")
public class PasswordProperties {

    private Long expiryTime = ChronoUnit.DAYS.getDuration().getSeconds();

    public Long getExpiryTime() {
        return expiryTime;
    }

    public void setExpiryTime(Long expiryTime) {
        this.expiryTime = expiryTime;
    }
}
