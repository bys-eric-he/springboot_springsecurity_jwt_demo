package com.springsecurity.jwt.demo.web.auth.user;

import com.google.common.collect.Maps;
import com.springsecurity.jwt.demo.common.constants.SecurityConstants;
import com.springsecurity.jwt.demo.common.constants.UserConstants;
import com.springsecurity.jwt.demo.common.utils.ResponseUtil;
import com.springsecurity.jwt.demo.common.utils.ResultUtil;
import com.springsecurity.jwt.demo.common.utils.jwt.JwtTokenUtil;
import com.springsecurity.jwt.demo.web.config.properties.UserAuthProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
public class UserTokenManager {

    @Autowired
    private UserAuthProperties userAuthProperties;
    @Autowired
    private UserSessionService userSessionService;

    /**
     * 颁发token
     * @param principal
     * @author eric.he
     * @return void
     */
    public void awardAccessToken(CustomerUserDetails principal, boolean isRefresh) {
        //颁发token 确定时间戳，保存在session中和token中
        long mill = System.currentTimeMillis();
        userSessionService.saveSession(principal);
        userSessionService.saveTokenTimestamp(principal.getUsername(),mill);

        Map<String,Object> param = new HashMap<>(2);
        param.put(UserConstants.USER_ID,principal.getId());
        param.put(SecurityConstants.TIME_STAMP,mill);

        String token = JwtTokenUtil.generateToken(principal.getUsername(), param,userAuthProperties.getExpiration());
        HashMap<String, String> map = Maps.newHashMapWithExpectedSize(2);
        map.put("token",token);
        map.put("tokenPrefix",userAuthProperties.getTokenPrefix());
        int code = isRefresh ? 201 : 200;
        ResponseUtil.outWithHeader(code, ResultUtil.success(),map);
    }

}