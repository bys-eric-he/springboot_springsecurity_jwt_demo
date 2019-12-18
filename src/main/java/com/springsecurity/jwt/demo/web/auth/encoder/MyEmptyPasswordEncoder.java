package com.springsecurity.jwt.demo.web.auth.encoder;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Slf4j
public class MyEmptyPasswordEncoder extends BCryptPasswordEncoder {

    @Override
    public String encode(CharSequence charSequence) {
        return String.valueOf(charSequence);
    }

    @Override
    public boolean matches(CharSequence charSequence, String s) {
        log.info("[MyEmptyPasswordEncoder] [matches] 密码:{}\t用户密码:{}",charSequence,s);
        return s.equals(charSequence.toString());
    }

}
