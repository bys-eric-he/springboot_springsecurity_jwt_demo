package com.springsecurity.jwt.demo.web.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/ignore")
@Api(tags = "IgnoreController", description = "不需要校验")
public class IgnoreController {


    @RequestMapping("/hello")
    @ApiOperation("Hello")
    public String hello() {
        return "hello";
    }

}