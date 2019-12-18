package com.springsecurity.jwt.demo.web.auth.encoder;

import com.springsecurity.jwt.demo.common.utils.encrypt.AESUtil;
import com.springsecurity.jwt.demo.web.config.properties.UserAuthProperties;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * 重写BCryptPasswordEncoder类的加密方法和密码对比方法
 */
@Slf4j
@Service
public class MyAesPasswordEncoder extends BCryptPasswordEncoder {

    @Autowired
    UserAuthProperties userAuthProperties;

    @Override
    public String encode(CharSequence pwd) {
        String end = super.encode(pwd);
        //end =AESUtil.encrypt(String.valueOf(pwd), AESUtil.getSecretKey());
        log.info("[MyAesPasswordEncoder] [encode] 加密的密码明文:{}\t加密后:{}", pwd, end);
        return end;
    }

    @Override
    public boolean matches(CharSequence charSequence, String encodedPassword) {
        if (StringUtils.isNotBlank(charSequence)) {
            log.info("[MyAesPasswordEncoder] [matches] 密码:{}\t用户加盐密码:{}", charSequence, encodedPassword);
            return super.matches(charSequence, encodedPassword);
            //String end = AESUtil.encrypt(String.valueOf(charSequence), AESUtil.getSecretKey());
            //log.info("[MyAesPasswordEncoder] [matches] 密码:{}\t加密后:{}\t用户密码:{}", charSequence, end, encodedPassword);
            //return encodedPassword.equals(end);
        }
        return false;
    }
}