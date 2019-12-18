package com.springsecurity.jwt.demo.web.auth.user;

/**
 * 用来管理用户会话信息，登录后储存，注销则清空
 */
public interface UserSessionService {

    void saveSession(CustomerUserDetails userDetails) ;

    CustomerUserDetails getSessionByUsername(String username);

    void destroySession(String username);

    void saveTokenTimestamp(String username,long mills);

    Long getTokenTimestamp(String username);
}
