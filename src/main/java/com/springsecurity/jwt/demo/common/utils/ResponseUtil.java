package com.springsecurity.jwt.demo.common.utils;

import com.alibaba.fastjson.JSON;
import com.baomidou.mybatisplus.toolkit.MapUtils;
import com.springsecurity.jwt.demo.core.result.Result;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

@Slf4j
public class ResponseUtil {

    public static void out(Result result) {
        out(200, result, null);
    }

    public static void out(int statusCode, Result result) {
        out(statusCode, result, null);
    }

    public static void outWithHeader(int statusCode, Result result, Map<String, String> map) {
        out(statusCode, result, map);
    }


    /**
     * 使用response输出JSON
     *
     * @param statusCode
     * @param result
     * @param header
     */
    public static void out(int statusCode, Result result, Map<String, String> header) {
        ServletOutputStream out = null;
        try {
            ServletRequestAttributes servletRequestAttributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (servletRequestAttributes != null) {
                HttpServletResponse response = servletRequestAttributes.getResponse();
                if (response != null && !response.isCommitted()) {
                    response.setCharacterEncoding("UTF-8");
                    response.setContentType("application/json;charset=UTF-8");
                    response.setStatus(statusCode);
                    if (MapUtils.isNotEmpty(header)) {
                        header.forEach(response::setHeader);
                    }
                    out = response.getOutputStream();
                    out.write(JSON.toJSONString(result).getBytes());
                }
            }
        } catch (Exception e) {
            log.error("[ResponseUtil] 响应出错 ", e);
        } finally {
            if (out != null) {
                try {
                    out.flush();
                    out.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}