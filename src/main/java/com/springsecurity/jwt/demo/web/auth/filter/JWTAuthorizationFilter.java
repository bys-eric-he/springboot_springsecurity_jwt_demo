package com.springsecurity.jwt.demo.web.auth.filter;

import com.springsecurity.jwt.demo.common.utils.jwt.JwtTokenUtil;
import com.springsecurity.jwt.demo.web.auth.user.UserSessionService;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.lang.reflect.Array;
import java.util.Collection;
import java.util.Collections;

/**
 * 验证用户权限的拦截器
 * 只要告诉spring-security该用户是否已登录，是什么角色，拥有什么权限就可以了
 */
@Slf4j
public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

    //@Autowired
    //private UserSessionService userSessionService;

    public static final String TOKEN_HEADER = "Authorization";
    public static final String TOKEN_PREFIX = "Bearer";

    public JWTAuthorizationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws IOException, ServletException {
        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Allow-Methods", "*");
        response.setHeader("Access-Control-Max-Age", "3600");
        response.setHeader("Access-Control-Allow-Headers", "*");
        if (request.getMethod().equals("OPTIONS")) {
            response.setStatus(HttpServletResponse.SC_OK);
            return;
        }
        String tokenHeader = request.getHeader(TOKEN_HEADER);
        log.info("授权1->" + tokenHeader);

        // 如果请求头中有token，则进行解析，并且设置认证信息
        if (tokenHeader != null && tokenHeader.startsWith(TOKEN_PREFIX)) {
            //如果有accessToken的请求头，取出token，解析token，解析成功说明token正确，将解析出来的用户信息放到SpringSecurity的上下文中
            SecurityContextHolder.getContext().setAuthentication(getAuthentication(tokenHeader));
            super.doFilterInternal(request, response, chain);
        }

        /*
        如果请求头中没有Authorization信息则直接放行了。
        前端发起请求的时候将token放在请求头中，在过滤器中对请求头进行解析。
        如果有accessToken的请求头（可以自已定义名字），取出token，解析token，解析成功说明token正确，将解析出来的用户信息放到SpringSecurity的上下文中
        如果有accessToken的请求头，解析token失败（无效token，或者过期失效），取不到用户信息，放行
        没有accessToken的请求头，放行，这里可能有人会疑惑，为什么token失效都要放行呢？
        这是因为SpringSecurity会自己去做登录的认证和权限的校验，靠的就是我们放在SpringSecurity上下文中的SecurityContextHolder.getContext().setAuthentication(authentication);
        没有拿到authentication，放行了，SpringSecurity还是会走到认证和校验，这个时候就会发现没有登录没有权限，就会被AuthenticationEntryPoint实现类拦截。
        **/
        chain.doFilter(request, response);
    }

    /**
     * 这里从token中获取用户信息并新建一个token
     * 解析token，检查是否能从token中取出username，如果有就算成功了\
     * 再根据该username创建一个UsernamePasswordAuthenticationToken对象
     *
     * @param tokenHeader
     * @return
     */
    private UsernamePasswordAuthenticationToken getAuthentication(String tokenHeader) {
        String token = tokenHeader.replace(TOKEN_PREFIX, "");
        String username = JwtTokenUtil.parseTokenGetUsername(token);
        String role = JwtTokenUtil.getUserRole(token);
        log.info("role->" + role);
        if (username != null) {
            //假如能从token中获取用户名就该token验证成功
            //创建一个UsernamePasswordAuthenticationToken该token包含用户的角色信息，而不是一个空的ArrayList，查看一下源代码是有以下一个构造方法的。
            return new UsernamePasswordAuthenticationToken(username, role,
                    Collections.singleton(new SimpleGrantedAuthority(role))
            );
        }


        //避免每次请求都请求数据库查询用户信息，从缓存中查询
        /*UserDetails userDetails = userSessionService.getSessionByUsername(username);
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            //UserDetails userDetails = customerUserDetailService.loadUserByUsername(username);
            if (userDetails != null) {
                if (JwtTokenUtil.validateToken(token, userDetails)) {
                    //必须token解析的时间戳和session保存的一致
                    return new UsernamePasswordAuthenticationToken(userDetails, userDetails.getPassword(), userDetails.getAuthorities());
                }
            }
        }*/


        return null;
    }
}