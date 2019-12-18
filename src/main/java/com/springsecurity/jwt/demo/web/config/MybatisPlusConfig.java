package com.springsecurity.jwt.demo.web.config;

import com.baomidou.mybatisplus.plugins.PaginationInterceptor;
import org.mybatis.spring.annotation.MapperScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * 扫描所有的mapper接口
 */
@MapperScan({"com.springsecurity.jwt.demo.dao.mapper"})
@Configuration
public class MybatisPlusConfig {
    /**
     * 分页插件，自动识别数据库类型
     * 多租户，请参考官网【插件扩展】
     */
    @Bean
    public PaginationInterceptor paginationInterceptor() {
        return new PaginationInterceptor().setDialectType("mysql");
    }
}