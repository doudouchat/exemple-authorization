package com.exemple.authorization.password.properties;

import java.time.temporal.ChronoUnit;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import lombok.Getter;
import lombok.Setter;

@Component
@ConfigurationProperties(prefix = "authorization.password")
@Getter
@Setter
public class PasswordProperties {

    private Long expiryTime = ChronoUnit.DAYS.getDuration().getSeconds();

}
