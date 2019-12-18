package com.springsecurity.jwt.demo.web.controller;

import com.alibaba.fastjson.JSON;
import com.google.common.collect.Maps;
import com.springsecurity.jwt.demo.common.dto.UserDto;
import com.springsecurity.jwt.demo.common.utils.ResultUtil;
import com.springsecurity.jwt.demo.core.error.ErrorCodeConstants;
import com.springsecurity.jwt.demo.core.exception.BizServiceException;
import com.springsecurity.jwt.demo.core.result.Result;
import com.springsecurity.jwt.demo.service.IUserService;
import com.springsecurity.jwt.demo.web.auth.user.UserTokenManager;
import com.springsecurity.jwt.demo.web.config.properties.UserAuthProperties;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;

@Api(tags = "UserController", description = "用户管理")
@RestController
@RequestMapping("/user")
public class UserController {

    @Autowired
    IUserService userService;
    @Autowired
    UserTokenManager userTokenManager;
    @Autowired
    UserAuthProperties userAuthProperties;

    @GetMapping("/hello")
    @ApiOperation("Hello")
    public Result<String> hello() {
        return ResultUtil.success("hello world");
    }


    @Secured("ROLE_SUPER")
    @GetMapping("/super")
    @ApiOperation("ROLE_SUPER 角色访问")
    public Result<String> superRole() {
        return ResultUtil.success("hello world,super可以访问");
    }


    @Secured("ROLE_SUPPER_ADMIN")
    @GetMapping("/admin")
    @ApiOperation("ROLE_ADMIN 角色访问")
    public Result<String> admin() {
        return ResultUtil.success("hello world,admin可以访问");
    }

    @PreAuthorize("hasRole('ADMIN') AND hasRole('EMPLOYEE')")
    @GetMapping("/employee")
    @ApiOperation("hasRole('ADMIN') AND hasRole('EMPLOYEE') 角色访问")
    public Result<String> employee() {
        return ResultUtil.success("hello world,employee可以访问");
    }

    /**
     * 注册
     *
     * @param userDto
     * @param role
     * @return
     */
    @ApiOperation(value = "注册")
    @RequestMapping(value = "/register", method = RequestMethod.POST)
    @ResponseBody
    public Result<String> register(@Validated @RequestBody UserDto userDto, String role, BindingResult result) {
        if (result.hasErrors()) {
            throw new BizServiceException(ErrorCodeConstants.BAD_REQUEST_ERROR, result.getFieldError().getDefaultMessage());
        }
        String res = userService.register(userDto.getUsername(), userDto.getPassword(), role);
        return ResultUtil.success(res);
    }

    @ApiOperation(value = "登录以后返回token")
    @RequestMapping(value = "/login", method = RequestMethod.POST)
    @ResponseBody
    public Result<String> login(@Validated @RequestBody UserDto userDto, BindingResult result) throws Exception{
        if (result.hasErrors()) {
            throw new BizServiceException(ErrorCodeConstants.BAD_REQUEST_ERROR, result.getFieldError().getDefaultMessage());
        }

        String token = userService.login(userDto.getUsername(), userDto.getPassword());
        HashMap<String, String> map = Maps.newHashMapWithExpectedSize(2);
        map.put("token", token);
        map.put("tokenPrefix",userAuthProperties.getTokenPrefix());
        return ResultUtil.success(JSON.toJSONString(map));
    }

    @ApiOperation(value = "退出清除token")
    @RequestMapping(value = "/logout", method = RequestMethod.GET)
    @ResponseBody
    public Result<String> logout(HttpServletRequest request, HttpServletResponse response){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication!=null){
            new SecurityContextLogoutHandler().logout(request,response,authentication);
        }
        return ResultUtil.success();
    }

    @ApiOperation(value = "刷新token")
    @RequestMapping(value = "/refresh-token", method = RequestMethod.GET)
    @ResponseBody
    public Result<String> refreshToken(HttpServletRequest request, String token) {
        String value = request.getHeader(userAuthProperties.getTokenHeader());
        if (value==null){
            value=token;
        }
        String refreshToken = userService.refreshToken(value);
        if (refreshToken == null) {
            throw new BizServiceException();
        }
        HashMap<String, String> map = Maps.newHashMapWithExpectedSize(2);
        map.put("token", token);
        map.put("tokenPrefix",refreshToken);
        return ResultUtil.success(JSON.toJSONString(map));
    }
}