package com.springsecurity.jwt.demo.web.auth.filter;

import com.springsecurity.jwt.demo.common.constants.SecurityConstants;
import com.springsecurity.jwt.demo.common.constants.UserConstants;
import com.springsecurity.jwt.demo.common.utils.jwt.JwtTokenUtil;
import com.springsecurity.jwt.demo.web.auth.user.CustomerUserDetails;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.security.auth.login.FailedLoginException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.file.AccessDeniedException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

/**
 * 验证用户登录信息的拦截器
 * UsernamePasswordAuthenticationFilter拦截登陆请求
 */
@Slf4j
public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    public static final String TOKEN_PREFIX = "Bearer";

    private AuthenticationManager authenticationManager;

    /**
     * 当向服务器发起登陆请求路径为/user/login的API时会被拦截
     *
     * @param authenticationManager
     */
    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
        super.setFilterProcessesUrl("/user/login");
    }

    /**
     * 请求登录
     * @param request
     * @param response
     * @return
     * @throws AuthenticationException
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {
        // 从输入流中获取到登录的信息,通过输入的信息框架去数据库中查找是否匹配，然后成功或者失败，结束
        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Allow-Methods", "*");
        response.setHeader("Access-Control-Max-Age", "3600");
        response.setHeader("Access-Control-Allow-Headers", "*");
        if (request.getMethod().equals("OPTIONS")) {
            response.setStatus(HttpServletResponse.SC_OK);
            return null;
        }
        //response.setHeader("Access-Control-Allow-Headers","Authorization");
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        //LoginUser loginUser = new ObjectMapper().readValue(request.getInputStream(), LoginUser.class);
        //创建一个UsernamePasswordAuthenticationToken该token包含用户的角色信息，而不是一个空的ArrayList，查看一下源代码是有以下一个构造方法的。
        //调用authenticationManager.authenticate()让spring-security去进行验证就可以了，不用自己查数据库再对比密码了，这一步交给spring去操作
        return authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password, new ArrayList<>())
        );
    }

    /**
     * 成功验证后调用的方法
     * 如果验证成功，就生成token并返回
     *
     * @param request
     * @param response
     * @param chain
     * @param authResult
     * @throws IOException
     * @throws ServletException
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
        // 查看源代码会发现调用getPrincipal()方法会返回一个实现了`UserDetails`接口的对象
        // 所以就是JwtUser啦
        CustomerUserDetails jwtUser = (CustomerUserDetails) authResult.getPrincipal();
        log.info("-----------这里是第一个拦截------------------");

        long mill = System.currentTimeMillis();

        //userSessionService.saveSession(jwtUser);
        //userSessionService.saveTokenTimestamp(jwtUser.getUsername(), mill);

        Map<String, Object> param = new HashMap<>(4);
        param.put(UserConstants.USER_ID, jwtUser.getId());
        param.put(UserConstants.ROLE_CLAIMS,"ROLE_SUPPER_ADMIN");
        param.put(SecurityConstants.TIME_STAMP, mill);

        //创建token
        String token = JwtTokenUtil.generateToken(jwtUser.getUsername(), param);
        // 但是这里创建的token只是单纯的token
        // 按照jwt的规定，最后请求的格式应该是 `Bearer token`
        response.setHeader("Access-Control-Expose-Headers", "token");
        response.setHeader("Access-Control-Expose-Headers", "tokenPrefix");
        response.setHeader("token", token);//JwtTokenUtils.TOKEN_PREFIX +
        response.setHeader("tokenPrefix", TOKEN_PREFIX);
        log.info("--------->成功返回token<------------");
    }

    /**
     * 验证失败时候调用的方法
     * @param request
     * @param response
     * @param failed
     * @throws IOException
     * @throws ServletException
     */
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        log.error("authentication failed, reason: " + failed.getMessage());
    }
}