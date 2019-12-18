package com.springsecurity.jwt.demo.common.utils;

import com.springsecurity.jwt.demo.core.error.ErrorCache;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;

@Slf4j
public class FileUtil {
    private static final Logger LOGGER = LoggerFactory.getLogger(FileUtil.class);

    public static String readResourceFile(String path) {
        StringBuilder sb = new StringBuilder();
        try {
            InputStream is = ErrorCache.class.getClassLoader().getResourceAsStream(path);
            BufferedReader br = new BufferedReader(new InputStreamReader(is, "UTF-8"));
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line);
            }
        } catch (Exception e) {
            LOGGER.error("[读取文件失败] ", e);
        }
        return sb.toString();
    }
}