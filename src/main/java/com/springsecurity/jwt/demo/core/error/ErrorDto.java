package com.springsecurity.jwt.demo.core.error;

import lombok.Data;

@Data
public class ErrorDto {

    private String code;

    private String msg;

    private String innerMsg;

}