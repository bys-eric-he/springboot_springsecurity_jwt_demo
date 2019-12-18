package com.springsecurity.jwt.demo.core.error;

public interface ErrorCodeConstants {

    /**
     * 没有权限
     */
    String PERMISSION_DENY = "AUTH-PER-01";
    /**
     * 为获取到权限信息
     */
    String NOT_FOUND_PERMISSION_ERROR = "AUTH-PER-02";
    /**
     * 账号或密码不正确
     */
    String LOGIN_UNMATCH_ERROR = "AUTH-LOGIN-01";
    /**
     * 需要登录
     */
    String REQUIRED_LOGIN_ERROR = "AUTH-LOGIN-02";
    /**
     * 没有找到用户
     */
    String NOT_FOUND_USER_ERROR = "USER-SELECT-01";
    /**
     * 错误的请求
     */
    String BAD_REQUEST_ERROR = "BASE-REQUEST-01";

}