package com.springsecurity.jwt.demo.web.auth.handler;

import com.springsecurity.jwt.demo.common.utils.ResponseUtil;
import com.springsecurity.jwt.demo.common.utils.ResultUtil;
import com.springsecurity.jwt.demo.core.error.ErrorCodeConstants;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 登录后,访问没有权限请求处理
 */
@Slf4j
@Component
public class CustomerRestAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException, ServletException {
        log.error("authentication Denied, reason: " + accessDeniedException.getMessage());
        ResponseUtil.out(403, ResultUtil.failure(ErrorCodeConstants.PERMISSION_DENY,
                accessDeniedException.getMessage()));
    }
}
