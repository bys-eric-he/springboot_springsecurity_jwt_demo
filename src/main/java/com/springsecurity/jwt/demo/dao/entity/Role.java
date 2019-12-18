package com.springsecurity.jwt.demo.dao.entity;

import com.baomidou.mybatisplus.activerecord.Model;
import com.baomidou.mybatisplus.annotations.TableField;
import com.baomidou.mybatisplus.annotations.TableId;
import com.baomidou.mybatisplus.annotations.TableName;
import com.baomidou.mybatisplus.enums.IdType;

import lombok.Data;

import java.io.Serializable;
import java.util.Date;

@Data
@TableName("tbl_role")
public class Role extends Model<Role> {

    private static final long serialVersionUID = 1L;

    /**
     * 主键
     */
    @TableId(value = "id", type = IdType.AUTO)
    private Long id;
    /**
     * 角色
     */
    @TableField("role_name")
    private String roleName;
    @TableField("create_time")
    private Date createTime;

    @Override
    protected Serializable pkVal() {
        return this.id;
    }

}