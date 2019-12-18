package com.springsecurity.jwt.demo.web.auth.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.springsecurity.jwt.demo.web.auth.user.CustomerUserDetails;
import com.springsecurity.jwt.demo.web.auth.user.UserSessionService;
import com.springsecurity.jwt.demo.web.auth.user.UserTokenManager;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 登录成功处理类,登录成功后会调用里面的方法
 */
@Slf4j
@Component
public class CustomerAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    @Autowired
    private UserTokenManager userTokenManager;
    @Autowired
    private ObjectMapper objectMapper;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        log.info("登陆成功...");
        CustomerUserDetails principal = (CustomerUserDetails) authentication.getPrincipal();
        //保存用户信息到会话
        userTokenManager.awardAccessToken(principal, false);
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(objectMapper.writeValueAsString(authentication));
    }
}
