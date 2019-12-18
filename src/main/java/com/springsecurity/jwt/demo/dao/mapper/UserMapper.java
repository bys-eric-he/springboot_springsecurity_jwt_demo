package com.springsecurity.jwt.demo.dao.mapper;

import com.baomidou.mybatisplus.mapper.BaseMapper;
import com.springsecurity.jwt.demo.dao.entity.User;

public interface UserMapper extends BaseMapper<User> {

    User getUserRoleByUserName(String username);

    User lockUserById(Long id);
}
