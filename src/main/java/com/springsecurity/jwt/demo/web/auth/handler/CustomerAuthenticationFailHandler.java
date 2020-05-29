package com.springsecurity.jwt.demo.web.auth.handler;

import com.springsecurity.jwt.demo.common.utils.ResponseUtil;
import com.springsecurity.jwt.demo.common.utils.ResultUtil;
import com.springsecurity.jwt.demo.core.error.ErrorCodeConstants;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 登录账号密码错误等情况下,会调用的处理类
 */
@Slf4j
@Component
public class CustomerAuthenticationFailHandler implements AuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException authenticationException) throws IOException, ServletException {
        ResponseUtil.out(401, ResultUtil.failure(ErrorCodeConstants.LOGIN_UNMATCH_ERROR,
                authenticationException.getMessage()));
    }
}
