package com.springsecurity.jwt.demo.common.dto;

import lombok.Data;

@Data
public class UserRoleDto {

    private Long id;
    /**
     * 用户名
     */
    private String username;
    /**
     * 密码
     */
    private String password;

    private String roleName;
}
