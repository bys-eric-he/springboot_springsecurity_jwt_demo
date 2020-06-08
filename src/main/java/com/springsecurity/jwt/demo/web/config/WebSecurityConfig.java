package com.springsecurity.jwt.demo.web.config;

import com.springsecurity.jwt.demo.web.auth.encoder.MyAesPasswordEncoder;
import com.springsecurity.jwt.demo.web.auth.filter.CustomerJwtAuthenticationTokenFilter;
import com.springsecurity.jwt.demo.web.auth.filter.JWTAuthenticationFilter;
import com.springsecurity.jwt.demo.web.auth.handler.*;
import com.springsecurity.jwt.demo.web.auth.user.CustomerUserDetailService;
import com.springsecurity.jwt.demo.web.config.properties.IgnoreUrlsProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * 配置SpringSecurity,将处理器和我们的Jwt拦截器添加到Spring Security的配置中
 */
@Configuration
@EnableWebSecurity
//EnableGlobalMethodSecurity 控制@Secured权限注解
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private CustomerUserDetailService customerUserDetailService;
    @Autowired
    private CustomerAuthenticationFailHandler customerAuthenticationFailHandler;
    @Autowired
    private CustomerAuthenticationSuccessHandler customerAuthenticationSuccessHandler;
    @Autowired
    private CustomerJwtAuthenticationTokenFilter customerJwtAuthenticationTokenFilter;
    @Autowired
    private CustomerRestAccessDeniedHandler customerRestAccessDeniedHandler;
    @Autowired
    private CustomerLogoutSuccessHandler customerLogoutSuccessHandler;
    @Autowired
    private CustomerAuthenticationEntryPoint customerAuthenticationEntryPoint;
    @Autowired
    private IgnoreUrlsProperties ignoreUrlsProperties;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new MyAesPasswordEncoder();
    }

    public static void main(String[] args) {
        System.out.println(new MyAesPasswordEncoder().encode("eric.he"));
    }

    /**
     * 该方法定义认证用户信息获取的来源、密码校验的规则
     *
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        //自定义密码校验的规则
        //auth.authenticationProvider(new LoginAuthenticationProvider());

        //指定UserDetailsService的实现类，同时指定密码加密解密类。
        auth.userDetailsService(customerUserDetailService).passwordEncoder(passwordEncoder);
        //inMemoryAuthentication 从内存中获取
        auth.inMemoryAuthentication()
                //spring security5 以上必须配置加密
                .passwordEncoder(passwordEncoder);
    }

    /**
     * Spring Security两种资源放行策略, 通过HttpSecurity这种方式过虑是走Spring Security过虑器链，在过虑器链中给请求放行。
     * 有的资源放行是必须要走HttpSecurity这种方式的，比如API登录接口这种非静态资源，因为在过虑过程中还有其他事情要做。
     * antMatchers: ant的通配符规则
     * ?	匹配任何单字符
     * *	匹配0或者任意数量的字符，不包含"/"
     * **	匹配0或者更多的目录，包含"/"
     * 要用Security的密码加盐算法必须要写这部分
     * authorize：授权
     * authenticated：认证
     * authorizeRequests所有security全注解配置实现的开端，表示说明开始需要的权限
     * 需要的权限分两部分：第一部分是拦截的路径，第二部分是访问该路径需要的权限
     * antMatchers：拦截路径"/**所有路径"，permitAll()：任何权限都可以直接通行
     * anyRequest:任何的请求，authenticated认证后才可以访问
     * .and().csrf().disable();固定写法，表示使csrf（一种网络攻击技术）拦截失效
     * 测试用资源，需要验证了的用户才能访问
     * 其他都放行了
     * .anyRequest().permitAll()
     */
    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {

        httpSecurity
                .headers()
                .frameOptions().disable();
        //定义不需要保护的URL
        ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry registry = httpSecurity
                .authorizeRequests();

        //这里表示不需要权限校验
        ignoreUrlsProperties.getUrls().forEach(url -> registry.antMatchers(url).permitAll());

        httpSecurity
                //登录后,访问没有权限请求处理
                .exceptionHandling().accessDeniedHandler(customerRestAccessDeniedHandler)
                //匿名访问,没有权限的处理类
                .authenticationEntryPoint(customerAuthenticationEntryPoint);
        //将自定义的OncePerRequestFilter过虑器加入到Security执行链中，解析过来的请求是否有token
        httpSecurity
                .addFilterBefore(customerJwtAuthenticationTokenFilter, UsernamePasswordAuthenticationFilter.class);
        //将自定义UsernamePasswordAuthenticationFilter过虑器加入到Security执行链中，实现用户名、密码登录验证
        httpSecurity
                .addFilterAt(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
        httpSecurity
                //对请求的授权
                .authorizeRequests()
                .anyRequest()//任何请求
                .authenticated()//需要认证
                .and()
                .formLogin()
                // 配置登录页面 在 Spring Security 中，如果我们不做任何配置，默认的登录页面和登录接口的地址都是 /login，也就是说，默认会存在如下两个请求：
                // GET http://localhost:8089/login
                // POST http://localhost:8089/login
                // 当我们配置了 loginPage 为 /login.html 之后，这个配置从字面上理解，就是设置登录页面的地址为 /login.html。
                // 实际上它还有一个隐藏的操作，就是登录接口地址也设置成 /login.html 了。
                // 换句话说，新的登录页面和登录接口地址都是 /login.html，现在存在如下两个请求：
                // GET http://localhost:8089/login.html
                // POST http://localhost:8089/login.html
                // 前面的 GET 请求用来获取登录页面，后面的 POST 请求用来提交登录数据。
                //.loginPage("/login.html")
                // 在 SecurityConfig 中，我们可以通过 loginProcessingUrl 方法来指定登录接口地址,这样配置之后，登录页面地址和登录接口地址就分开了，各是各的。
                //.loginProcessingUrl("/doLogin")
                // 使用forward的方式，能拿到具体失败的原因,并且会将错误信息以SPRING_SECURITY_LAST_EXCEPTION的key的形式将AuthenticationException
                // 对象保存到request域中
                //.failureForwardUrl("/sys/loginFail")
                // 如果直接访问登录页面，则登录成功后重定向到这个页面，否则跳转到之前想要访问的页面.
                //.defaultSuccessUrl("/public/login/ok.html")
                .permitAll()
                .successHandler(customerAuthenticationSuccessHandler)
                .failureHandler(customerAuthenticationFailHandler)
                .permitAll()

                .and()
                //logout默认的url是 /logout,如果csrf启用，则请求方式是POST，否则请求方式是GET、POST、PUT、DELETE
                .logout()
                .logoutSuccessHandler(customerLogoutSuccessHandler)

                .and()
                //.addFilter(new JWTAuthenticationFilter(authenticationManager()))
                //.addFilter(new JWTAuthorizationFilter(authenticationManager()))
                // 禁用csrf模式
                .csrf().disable();
    }

    /**
     * Spring Security 两种资源放行策略
     * 通过WebSecurity这种方法不走Spring Security过虑器链，通常静态资源可以使用这种方式过虑放行，因为这些资源不需要权限就可以访问。
     *
     * @param web
     * @throws Exception
     */
    @Override
    public void configure(WebSecurity web) throws Exception {
        //权限控制需要忽略所有静态资源，不然登录页面未登录状态无法加载css等静态资源
        //web.ignoring().mvcMatchers("/static/**", "/img/**");
        ignoreUrlsProperties.getResources().forEach(resource -> web.ignoring().antMatchers(resource));
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", new CorsConfiguration().applyPermitDefaultValues());
        return source;
    }

    /**
     * 将JWTAuthenticationFilter过虑器注册到容器中
     *
     * @return
     * @throws Exception
     */
    @Bean
    public JWTAuthenticationFilter jwtAuthenticationFilter() throws Exception {
        JWTAuthenticationFilter filter = new JWTAuthenticationFilter(authenticationManagerBean());
        filter.setAuthenticationManager(authenticationManagerBean());
        filter.setAuthenticationSuccessHandler(customerAuthenticationSuccessHandler);
        filter.setAuthenticationFailureHandler(customerAuthenticationFailHandler);
        return filter;
    }
}