package com.springsecurity.jwt.demo.service.impl;

import com.alibaba.fastjson.JSON;
import com.baomidou.mybatisplus.mapper.EntityWrapper;
import com.baomidou.mybatisplus.service.impl.ServiceImpl;
import com.springsecurity.jwt.demo.common.constants.SecurityConstants;
import com.springsecurity.jwt.demo.common.constants.UserConstants;
import com.springsecurity.jwt.demo.common.utils.encrypt.AESUtil;
import com.springsecurity.jwt.demo.common.utils.jwt.JwtTokenUtil;
import com.springsecurity.jwt.demo.core.error.ErrorCodeConstants;
import com.springsecurity.jwt.demo.core.exception.BizServiceException;
import com.springsecurity.jwt.demo.dao.entity.Role;
import com.springsecurity.jwt.demo.dao.entity.User;
import com.springsecurity.jwt.demo.dao.entity.UserRole;
import com.springsecurity.jwt.demo.dao.mapper.UserMapper;
import com.springsecurity.jwt.demo.service.IRoleService;
import com.springsecurity.jwt.demo.service.IUserRoleService;
import com.springsecurity.jwt.demo.service.IUserService;
import com.springsecurity.jwt.demo.web.auth.encoder.MyAesPasswordEncoder;
import com.springsecurity.jwt.demo.web.auth.user.CustomerUserDetailService;
import com.springsecurity.jwt.demo.web.auth.user.CustomerUserDetails;
import com.springsecurity.jwt.demo.web.auth.user.UserSessionService;
import com.springsecurity.jwt.demo.web.config.properties.UserAuthProperties;
import io.jsonwebtoken.Claims;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
@Slf4j
public class UserServiceImpl extends ServiceImpl<UserMapper, User> implements IUserService {

    @Autowired
    private IUserRoleService userRoleService;

    @Autowired
    private IRoleService roleService;

    @Autowired
    CustomerUserDetailService customerUserDetailService;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    UserAuthProperties userAuthProperties;

    @Autowired
    UserSessionService userSessionService;

    private static final Logger LOGGER = LoggerFactory.getLogger(UserServiceImpl.class);

    /**
     * 登录功能
     *
     * @param username 用户名
     * @param password 密码
     * @return
     */
    @Override
    public String login(String username, String password) {
        UserDetails userDetails = customerUserDetailService.loadUserByUsername(username);
        if (userDetails == null) {
            throw new BadCredentialsException("用户不存在！");
        }
        if (!passwordEncoder.matches(password, userDetails.getPassword())) {
            throw new BadCredentialsException("密码错误！");
        }

        CustomerUserDetails customerUserDetails = (CustomerUserDetails) userDetails;

        long mill = System.currentTimeMillis();
        Map<String, Object> param = new HashMap<>(2);
        param.put(UserConstants.USER_ID, customerUserDetails.getId());
        param.put(SecurityConstants.TIME_STAMP, mill);

        return JwtTokenUtil.generateToken(userDetails.getUsername(), param, userAuthProperties.getExpiration());
    }

    /**
     * 刷新token
     * @param oldToken
     * @return
     */
    @Override
    public String refreshToken(String oldToken) {
        Claims claims= JwtTokenUtil.parseToken(oldToken);
        if(claims==null){
            throw new BizServiceException("token丢失, 不支持刷新, 请重新认证获取！");
        }
        //如果token已经过期，不支持刷新
        boolean isExpired =claims.getExpiration().before(new Date());
        if (isExpired){
            throw new BizServiceException("token已经过期, 不支持刷新, 请重新认证获取！");
        }
        //如果token在30分钟之内刚刷新过，返回原token
        if(JwtTokenUtil.tokenRefreshJustBefore(oldToken,30*60)){
            return oldToken;
        }else{
            long millis = System.currentTimeMillis();
            claims.put(SecurityConstants.TIME_STAMP, millis);
            Map<String, Object> param = new HashMap<>(4);
            param.put(UserConstants.USER_ID, claims.getId());
            param.put(SecurityConstants.TIME_STAMP, millis);
            return JwtTokenUtil.generateToken(JwtTokenUtil.parseTokenGetUsername(oldToken), param, userAuthProperties.getExpiration());
        }
    }

    /**
     * 获取用户信息
     *
     * @param username
     * @return void
     */
    @Override
    public User getUserRoleByUserName(String username) {
        User user = baseMapper.getUserRoleByUserName(username);
        LOGGER.info("[getUserRoleByUserName] 获取到user:{}", JSON.toJSONString(user));
        return user;
    }

    /**
     * 注册用户
     * @param username
     * @param password
     * @param roleName
     * @return
     */
    @Override
    public String register(String username,String password, String roleName) {
        int i = super.selectCount(new EntityWrapper<User>().eq("username", username));
        if (i == 0) {
            Role role = roleService.selectOne(new EntityWrapper<Role>().eq("role_name", roleName));
            if (role == null) {
                LOGGER.warn("[register] 注册用户 找不到该角色:{}", roleName);
                return "找不到该角色";
            }

            User user = new User();
            user.setUsername(username);
            user.setStatus(UserConstants.USER_STATUS_NORMAL);

            //aes加密
            String encrypt = passwordEncoder.encode(password);
            user.setPassword(encrypt);
            user.setCreateTime(new Date());
            user.setUpdateTime(new Date());
            super.insert(user);

            UserRole userRole = new UserRole();
            userRole.setUserId(user.getId());
            userRole.setRoleId(role.getId());
            userRole.setCreateTime(new Date());
            userRoleService.insert(userRole);
            return "成功注册!";
        }
        return "用户名已注册,请更换用户名!";
    }
}
