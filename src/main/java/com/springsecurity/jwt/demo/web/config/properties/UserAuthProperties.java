package com.springsecurity.jwt.demo.web.config.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * 登录认证相关配置类
 */
@Configuration
@ConfigurationProperties(
        prefix = "user-auth"
)
@Data
public class UserAuthProperties {

    /**
     * session过期时间，默认1天
     */
    private long sessionExpirationTime = 24 * 60 * 60 * 1000;


    /**
     * #JWT存储的请求头
     */
    private String tokenHeader;

    /**
     *#JWT加解密使用的密钥
     */
    private String secret;

    /**
     * #JWT的超期限时间(60*60*24)
     */
    private long expiration;

    /**
     * #JWT负载中拿到开头
     */
    private String tokenPrefix;

}