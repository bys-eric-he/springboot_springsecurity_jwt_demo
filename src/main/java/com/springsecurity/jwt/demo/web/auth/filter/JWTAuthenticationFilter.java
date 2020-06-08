package com.springsecurity.jwt.demo.web.auth.filter;

import com.springsecurity.jwt.demo.common.constants.SecurityConstants;
import com.springsecurity.jwt.demo.common.constants.UserConstants;
import com.springsecurity.jwt.demo.common.utils.ResponseUtil;
import com.springsecurity.jwt.demo.common.utils.ResultUtil;
import com.springsecurity.jwt.demo.common.utils.jwt.JwtTokenUtil;
import com.springsecurity.jwt.demo.core.error.ErrorCodeConstants;
import com.springsecurity.jwt.demo.web.auth.user.CustomerUserDetails;
import com.springsecurity.jwt.demo.web.auth.user.UserSessionService;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

/**
 * 验证用户登录信息的拦截器 UsernamePasswordAuthenticationFilter拦截登陆请求
 * 当我们想要在 Spring Security 自定义一个登录验证码或者将登录参数改为 JSON 的时候
 * 我们都需自定义过滤器继承自 AbstractAuthenticationProcessingFilter
 * 毫无疑问UsernamePasswordAuthenticationFilter#attemptAuthentication 方法
 * 就是在 AbstractAuthenticationProcessingFilter 类的 doFilter 方法中被触发的
 */
@Slf4j
public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    public static final String TOKEN_PREFIX = "Bearer";
    public static final String VALIDATE_CODE = "validateCode";
    public static final String USERNAME = "username";
    public static final String PASSWORD = "password";

    private AuthenticationManager authenticationManager;

    @Autowired
    private UserSessionService userSessionService;

    /**
     * 当向服务器发起登陆请求路径为GET http://localhost:8089/user/login?username=eric.he&password=admin 的API时会被拦截
     *
     * @param authenticationManager
     */
    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
        super.setFilterProcessesUrl("/user/login");
    }

    /**
     * attemptAuthentication：接收并解析用户凭证
     * 重写attemptAuthentication方法请求登录,如果逻辑和父类没有任何变化,可不用重写此方法,直接通过父类的方法进行登录验证
     * 首先通过 obtainUsername 和 obtainPassword 方法提取出请求里边的用户名/密码出来，提取方式就是 request.getParameter
     * 这也是为什么 Spring Security 中默认的表单登录要通过 key/value 的形式传递参数
     * 而不能传递 JSON 参数，如果像传递 JSON 参数，修改这里的逻辑即可。
     *
     * @param request
     * @param response
     * @return
     * @throws AuthenticationException
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {

        if (request.getMethod().equals("OPTIONS")) {
            response.setStatus(HttpServletResponse.SC_OK);
            return null;
        }

        //检测验证码是否正确
        this.checkValidateCode(request);

        String username = obtainUsername(request);
        String password = obtainPassword(request);

        // 构造一个 UsernamePasswordAuthenticationToken 对象，传入 username 和 password
        // username 对应了 UsernamePasswordAuthenticationToken 中的 principal 属性
        // password 则对应了它的 credentials 属性。
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password, new ArrayList<>());

        // 调用authenticationManager.authenticate()让spring-security去进行验证就可以了，不用自己查数据库再对比密码了，这一步交给spring去操作
        return authenticationManager.authenticate(authenticationToken);
    }

    /**
     * 检测请求传递过来的验证码和当前Session中生成的验证码是否一致
     *
     * @param request
     */
    protected void checkValidateCode(HttpServletRequest request) {
        HttpSession session = request.getSession();

        String sessionValidateCode = obtainSessionValidateCode(session);

        //获取后让Session中的验证码失效
        session.setAttribute(VALIDATE_CODE, null);
        String validateCodeParameter = obtainValidateCodeParameter(request);

        if (StringUtils.isEmpty(validateCodeParameter) || !sessionValidateCode.equalsIgnoreCase(validateCodeParameter)) {
            throw new AuthenticationServiceException("验证码错误！");
        }
    }

    /**
     * 获取Session中的验证码
     *
     * @param session
     * @return
     */
    protected String obtainSessionValidateCode(HttpSession session) {
        Object object = session.getAttribute(VALIDATE_CODE);
        return null == object ? "" : object.toString();
    }

    /**
     * 获取Http请求中的验证码
     *
     * @param request
     * @return
     */
    protected String obtainValidateCodeParameter(HttpServletRequest request) {
        Object object = request.getParameter(VALIDATE_CODE);
        return null == object ? "" : object.toString();
    }

    /**
     * 重写父类获取用户名方法
     *
     * @param request
     * @return
     */
    @Override
    protected String obtainUsername(HttpServletRequest request) {
        Object object = request.getParameter(USERNAME);
        return null == object ? "" : object.toString();
    }

    /**
     * 重写父类获取密码方法
     *
     * @param request
     * @return
     */
    @Override
    protected String obtainPassword(HttpServletRequest request) {
        Object object = request.getParameter(PASSWORD);
        return null == object ? "" : object.toString();
    }

    /**
     * successfulAuthentication 用户成功登录后，这个方法会被调用
     * 我们在这个方法里生成token并返回
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
        // 在这里有一段很重要的代码，就是 SecurityContextHolder.getContext().setAuthentication(authResult);
        // 登录成功的用户信息被保存在这里，也就是说，在任何地方，如果我们想获取用户登录信息
        // 都可以从 SecurityContextHolder.getContext() 中获取到，想修改，也可以在这里修改。
        SecurityContextHolder.getContext().setAuthentication(authResult);
        // 查看源代码会发现调用getPrincipal()方法会返回一个实现了`UserDetails`接口的对象 所以就是JwtUser啦
        CustomerUserDetails jwtUser = (CustomerUserDetails) authResult.getPrincipal();
        log.info("-----------这里是第一个拦截------------------");

        long mill = System.currentTimeMillis();

        userSessionService.saveSession(jwtUser);
        userSessionService.saveTokenTimestamp(jwtUser.getUsername(), mill);

        Map<String, Object> param = new HashMap<>(4);
        param.put(UserConstants.USER_ID, jwtUser.getId());
        param.put(UserConstants.ROLE_CLAIMS, "ROLE_SUPPER_ADMIN");
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
     * unsuccessfulAuthentication 验证失败时候调用的方法
     *
     * @param request
     * @param response
     * @param failed
     * @throws IOException
     * @throws ServletException
     */
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        log.error("authentication failed, reason: " + failed.getMessage());
        ResponseUtil.out(403, ResultUtil.failure(ErrorCodeConstants.PERMISSION_DENY,
                failed.getMessage()));
    }
}