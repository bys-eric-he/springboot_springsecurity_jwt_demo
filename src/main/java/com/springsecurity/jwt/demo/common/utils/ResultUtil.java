package com.springsecurity.jwt.demo.common.utils;

import com.springsecurity.jwt.demo.core.error.ErrorCache;
import com.springsecurity.jwt.demo.core.result.Result;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

@Slf4j
public class ResultUtil {

    private static final int SUCCESS_CODE = 1;
    private static final int FAILURE_CODE = 0;
    private static final String BASE_ERROR_CODE = "BASE-SYS-ERR-0";
    private static final String BASE_ERROR_MSG = "网络繁忙，请稍后再试";

    /**
     * 返回成功result
     * @param <T>
     * @return
     */
    public static <T> Result<T> success(){
        return success(null);
    }

    /**
     * 返回成功result
     * @param data
     * @param <T>
     * @return
     */
    public static <T>  Result<T> success(T data){
        return new Result<>(SUCCESS_CODE, null, null, data);
    }



    /**
     * 返回失败result
     * @param <T>
     * @return
     */
    public static <T>  Result<T> failureDefaultError(){
        return failure(BASE_ERROR_CODE, BASE_ERROR_MSG,null);
    }


    /**
     * 返回失败result
     * @param <T>
     * @return
     */
    public static <T>  Result<T> failure(String errCode){
        return failure(errCode,null,null);
    }



    /**
     * 返回失败result
     * @param <T>
     * @return
     */
    public static <T>  Result<T> failure(String errCode,String errMsg){
        return failure(errCode,errMsg,null);
    }

    /**
     * 返回失败result
     * @param data
     * @param <T>
     * @return
     */
    public static <T>  Result<T> failure(String errCode,String errMsg,T data){
        return getFailResult(errCode, errMsg, data);
    }


    /**
     * 获取错误码和错误信息，返回result对象
     * @param errCode
     * @param errMsg
     * @param data
     * @param <T>
     * @return
     */
    private static <T> Result<T> getFailResult(String errCode, String errMsg, T data) {
        if (StringUtils.isNoneEmpty(errCode)){
            if (StringUtils.isEmpty(errMsg)){
                //获取msg
                errMsg = ErrorCache.getMsg(errCode) ;
                if (StringUtils.isEmpty(errMsg)){
                    log.info("[获取错误码] 未能获取错误信息 errCode：{}",errCode);
                    errMsg = BASE_ERROR_MSG;
                }
            }
        }else {
            errCode = BASE_ERROR_CODE;
            errMsg = BASE_ERROR_MSG;
        }
        return new Result<>(FAILURE_CODE, errCode, errMsg, data);
    }
}