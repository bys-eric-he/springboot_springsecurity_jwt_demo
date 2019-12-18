package com.springsecurity.jwt.demo.service.impl;

import com.baomidou.mybatisplus.service.impl.ServiceImpl;
import com.springsecurity.jwt.demo.dao.entity.UserRole;
import com.springsecurity.jwt.demo.dao.mapper.UserRoleMapper;
import com.springsecurity.jwt.demo.service.IUserRoleService;
import org.springframework.stereotype.Service;

@Service
public class UserRoleServiceImpl extends ServiceImpl<UserRoleMapper, UserRole> implements IUserRoleService {

}
