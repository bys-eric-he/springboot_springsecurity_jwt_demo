package com.springsecurity.jwt.demo.core.result;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class Result<T> {

    /**
     * 响应码
     */
    private Integer resCode;

    /**
     * 错误码
     */
    private String errCode;

    /**
     * 错误信息
     */
    private String errMsg;

    /**
     * 数据
     */
    private T data;
}
