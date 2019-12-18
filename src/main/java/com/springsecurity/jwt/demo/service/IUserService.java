package com.springsecurity.jwt.demo.service;

import com.baomidou.mybatisplus.service.IService;
import com.springsecurity.jwt.demo.dao.entity.User;

public interface IUserService extends IService<User> {
    /**
     * 登录功能
     * @param username 用户名
     * @param password 密码
     * @return 生成的JWT的token
     */
    String login(String username,String password) throws Exception;

    /**
     * 获取用户信息
     * @param username
     */
    User getUserRoleByUserName(String username);

    /**
     * 注册
     * @param username
     * @param password
     * @param roleName
     * @return
     */
    String register(String username,String password, String roleName);

    /**
     * 刷新token
     * @param oldToken
     * @return
     */
    String refreshToken(String oldToken);
}