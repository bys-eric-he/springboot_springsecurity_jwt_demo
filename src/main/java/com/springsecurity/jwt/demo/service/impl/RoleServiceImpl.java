package com.springsecurity.jwt.demo.service.impl;

import com.baomidou.mybatisplus.service.impl.ServiceImpl;
import com.springsecurity.jwt.demo.dao.entity.Role;
import com.springsecurity.jwt.demo.dao.mapper.RoleMapper;
import com.springsecurity.jwt.demo.service.IRoleService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

@Service
public class RoleServiceImpl extends ServiceImpl<RoleMapper, Role> implements IRoleService {


    /**
     * 配置调用该业务层方法需要的权限为：ROLE_ADMIN
     * @return
     */
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @Override
    public String mustAdmin() {
        return "业务层,只有ROLE_ADMIN权限可见.";
    }
}

