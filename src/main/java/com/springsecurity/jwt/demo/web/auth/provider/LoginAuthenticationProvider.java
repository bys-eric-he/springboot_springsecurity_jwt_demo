package com.springsecurity.jwt.demo.web.auth.provider;

import com.springsecurity.jwt.demo.web.auth.user.CustomerUserDetailService;
import com.springsecurity.jwt.demo.web.auth.user.CustomerUserDetails;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class LoginAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    CustomerUserDetailService userDetailsService;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 获取前端表单中输入后返回的用户名、密码
        String userName = (String) authentication.getPrincipal();
        String password = (String) authentication.getCredentials();

        UserDetails userDetails = userDetailsService.loadUserByUsername(userName);

        CustomerUserDetails customerUserDetails = (CustomerUserDetails) userDetails;

        if (!passwordEncoder.matches(password, customerUserDetails.getPassword())) {
            throw new BadCredentialsException("密码错误！");
        }

        return new UsernamePasswordAuthenticationToken(userDetails, userDetails.getPassword(), userDetails.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return true;
    }
}