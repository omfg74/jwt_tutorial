package com.example.springsecurity.jwt;

import com.google.common.net.HttpHeaders;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
//@ConfigurationProperties(prefix = "application.jwt")
public class JwtConfig {

    @Value("${application.jwt.secret.key}")
    private String secretKey;
    @Value("${application.jwt.token.prefix}")
    private String tokenPrefix;
    @Value("${application.jwt.token.expiration.after.days}")
    private Integer tokenExpiredAfterDays;


    public JwtConfig() {
    }

    public String getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
    }

    public String getTokenPrefix() {
        return tokenPrefix;
    }

    public void setTokenPrefix(String tokenPrefix) {
        this.tokenPrefix = tokenPrefix;
    }

    public Integer getTokenExpiredAfterDays() {
        return tokenExpiredAfterDays;
    }

    public void setTokenExpiredAfterDays(Integer tokenExpiredAfterDays) {
        this.tokenExpiredAfterDays = tokenExpiredAfterDays;
    }


    public String getAuthorizationHeader(){
        return HttpHeaders.AUTHORIZATION;
    }
}
