package com.springsecurity.jwt.demo.web.auth.user;

import com.springsecurity.jwt.demo.common.constants.UserConstants;
import com.springsecurity.jwt.demo.dao.entity.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

@Slf4j
public class CustomerUserDetails extends User implements UserDetails {

    private Collection<? extends GrantedAuthority> authorities;

    public CustomerUserDetails(User user){
        this.setId(user.getId());
        this.setUsername(user.getUsername());
        this.setPassword(user.getPassword());
        this.setRoles(user.getRoles());
        this.setStatus(user.getStatus());
    }

    public void setAuthorities(Collection<? extends GrantedAuthority> authorities) {
        this.authorities = authorities;
    }

    /**
     * 添加用户拥有的权限和角色
     * @return
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    /**
     * 账户是否过期
     * @return
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     * 是否禁用
     * @return
     */
    @Override
    public boolean isAccountNonLocked() {
        return  true;
    }

    /**
     * 密码是否过期
     * @return
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * 是否启用
     * @return
     */
    @Override
    public boolean isEnabled() {
        return UserConstants.USER_STATUS_NORMAL.equals(this.getStatus());
    }
}
