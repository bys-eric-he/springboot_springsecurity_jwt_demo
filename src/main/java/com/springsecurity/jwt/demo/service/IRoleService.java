package com.springsecurity.jwt.demo.service;

import com.baomidou.mybatisplus.service.IService;
import com.springsecurity.jwt.demo.dao.entity.Role;

public interface IRoleService extends IService<Role> {

    String mustAdmin();
}