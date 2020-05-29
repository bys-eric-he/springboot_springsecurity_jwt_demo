package com.springsecurity.jwt.demo.web.auth.handler;

import com.springsecurity.jwt.demo.common.utils.ResponseUtil;
import com.springsecurity.jwt.demo.common.utils.ResultUtil;
import com.springsecurity.jwt.demo.core.error.ErrorCodeConstants;
import com.springsecurity.jwt.demo.web.auth.user.CustomerUserDetails;
import com.springsecurity.jwt.demo.web.auth.user.UserSessionService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@Component
public class CustomerLogoutSuccessHandler implements LogoutSuccessHandler {

    @Autowired
    private UserSessionService userSessionService;

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        if (authentication != null) {
            Object principalTemp = authentication.getPrincipal();
            if (principalTemp instanceof CustomerUserDetails) {
                CustomerUserDetails principal = (CustomerUserDetails) principalTemp;
                //清除session会话信息
                userSessionService.destroySession(principal.getUsername());
                ResponseUtil.out(ResultUtil.success("注销token成功!"));
            }
        }
        ResponseUtil.out(ResultUtil.failure(ErrorCodeConstants.BAD_REQUEST_ERROR));
    }
}