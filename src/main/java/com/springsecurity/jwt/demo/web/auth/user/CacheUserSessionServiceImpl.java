package com.springsecurity.jwt.demo.web.auth.user;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.springsecurity.jwt.demo.web.config.properties.UserAuthProperties;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

/**
 * CacheUserSessionServiceImpl
 * 使用guava的cache实现的，存储用户会话session
 */
@Component
public class CacheUserSessionServiceImpl implements UserSessionService , InitializingBean {

    @Autowired
    private UserAuthProperties userAuthProperties;

    private Cache<String,Object> userDetailsCache;
    private static final String USER_SESSION_PREFIX = "USER-SESSION:";
    private static final String USER_TOKEN_TIMESTAMP_PREFIX = "USER-TOKEN-TIMESTAMP:";


    @Override
    public void saveSession(CustomerUserDetails userDetails) {
        String username = userDetails.getUsername();
        String key = USER_SESSION_PREFIX + username;
        userDetailsCache.put(key,userDetails);
    }

    @Override
    public CustomerUserDetails getSessionByUsername(String username) {
        String key = USER_SESSION_PREFIX + username;
        return (CustomerUserDetails) userDetailsCache.getIfPresent(key);
    }

    @Override
    public void destroySession(String username) {
        String key = USER_SESSION_PREFIX + username;
        String key1 = USER_TOKEN_TIMESTAMP_PREFIX + username;
        userDetailsCache.invalidate(key);
        userDetailsCache.invalidate(key1);
    }

    @Override
    public void afterPropertiesSet() {
        userDetailsCache = CacheBuilder.newBuilder()
                .expireAfterWrite(userAuthProperties.getSessionExpirationTime(), TimeUnit.MILLISECONDS)
                .build();
    }

    @Override
    public void saveTokenTimestamp(String username, long mills) {
        String key = USER_TOKEN_TIMESTAMP_PREFIX + username;
        userDetailsCache.put(key,mills);
    }

    @Override
    public Long getTokenTimestamp(String username) {
        String key = USER_TOKEN_TIMESTAMP_PREFIX + username;
        return (Long) userDetailsCache.getIfPresent(key);
    }
}