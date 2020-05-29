package com.springsecurity.jwt.demo.web.auth.filter;

import com.springsecurity.jwt.demo.common.constants.SecurityConstants;
import com.springsecurity.jwt.demo.common.utils.ResponseUtil;
import com.springsecurity.jwt.demo.common.utils.ResultUtil;
import com.springsecurity.jwt.demo.common.utils.jwt.JwtTokenUtil;
import com.springsecurity.jwt.demo.core.error.ErrorCodeConstants;
import com.springsecurity.jwt.demo.web.auth.user.CustomerUserDetailService;
import com.springsecurity.jwt.demo.web.auth.user.CustomerUserDetails;
import com.springsecurity.jwt.demo.web.auth.user.UserSessionService;
import com.springsecurity.jwt.demo.web.auth.user.UserTokenManager;
import com.springsecurity.jwt.demo.web.config.properties.UserAuthProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 定义我们自己的JWT拦截器，在请求到达目标之前对Token进行校验
 * 在请求过来的时候,解析请求头中的token,再解析token得到用户信息,再存到SecurityContextHolder中
 */
@Slf4j
@Component
public class CustomerJwtAuthenticationTokenFilter extends OncePerRequestFilter {

    @Autowired
    CustomerUserDetailService customerUserDetailService;
    @Autowired
    UserSessionService userSessionService;
    @Autowired
    UserTokenManager userTokenManager;
    @Autowired
    UserAuthProperties userAuthProperties;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        //请求头为 access Token
        //请求体为 Bearer token
        String authHeader = request.getHeader(userAuthProperties.getTokenHeader());

        if (authHeader != null && authHeader.startsWith(userAuthProperties.getTokenPrefix())) {
            //请求头有token
            final String authToken = authHeader.substring(userAuthProperties.getTokenPrefix().length());

            String username;
            Claims claims;
            try {
                claims = JwtTokenUtil.parseToken(authToken);
                username = claims.getSubject();
            } catch (ExpiredJwtException expiredJwtException) {
                //token过期
                claims = expiredJwtException.getClaims();
                username = claims.getSubject();
                CustomerUserDetails customerUserDetails = userSessionService.getSessionByUsername(username);
                if (customerUserDetails != null) {
                    //session未过期，比对时间戳是否一致，是则重新颁发token
                    if (isSameTimestampToken(username, expiredJwtException.getClaims())) {
                        userTokenManager.awardAccessToken(customerUserDetails, true);
                    }
                    else{
                        ResponseUtil.out(HttpStatus.UNAUTHORIZED.value(),
                                ResultUtil.failure(ErrorCodeConstants.REQUIRED_LOGIN_ERROR,
                                        expiredJwtException.getMessage()));
                        return;
                    }
                }else{
                    //直接放行,交给后面的handler处理,如果当前请求是需要访问权限,则会由CustomerRestAccessDeniedHandler处理
                    chain.doFilter(request, response);
                    return;
                }

            }

            //避免每次请求都请求数据库查询用户信息，从缓存中查询
            UserDetails userDetails = userSessionService.getSessionByUsername(username);
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                //UserDetails userDetails = customerUserDetailService.loadUserByUsername(username);
                if (userDetails != null) {
                    if (JwtTokenUtil.validateToken(authToken, userDetails)) {
                        //必须token解析的时间戳和session保存的一致
                        UsernamePasswordAuthenticationToken authentication =
                                new UsernamePasswordAuthenticationToken(userDetails, userDetails.getPassword(),
                                        userDetails.getAuthorities());
                        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                        //如果有accessToken的请求头，取出token，解析token，解析成功说明token正确，将解析出来的用户信息放到SpringSecurity的上下文中
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                    }
                }
            }
        }

         /*
        如果请求头中没有Authorization信息则直接放行了。
        前端发起请求的时候将token放在请求头中，在过滤器中对请求头进行解析。
        如果有accessToken的请求头（可以自已定义名字），取出token，解析token，解析成功说明token正确，将解析出来的用户信息放到SpringSecurity的上下文中
        如果有accessToken的请求头，解析token失败（无效token，或者过期失效），取不到用户信息，放行
        没有accessToken的请求头，放行，这里可能有人会疑惑，为什么token失效都要放行呢？
        这是因为SpringSecurity会自己去做登录的认证和权限的校验，靠的就是我们放在SpringSecurity上下文中的SecurityContextHolder.getContext()
        .setAuthentication(authentication);
        没有拿到authentication，放行了，SpringSecurity还是会走到认证和校验，这个时候就会发现没有登录没有权限，就会被AuthenticationEntryPoint实现类拦截。
        **/
        chain.doFilter(request, response);
    }

    /**
     * 判断是否同一个时间戳
     *
     * @param username
     * @param claims
     * @return
     */
    private boolean isSameTimestampToken(String username, Claims claims) {
        Long timestamp = userSessionService.getTokenTimestamp(username);
        Long jwtTimestamp = (Long) claims.get(SecurityConstants.TIME_STAMP);
        return timestamp.equals(jwtTimestamp);
    }
}