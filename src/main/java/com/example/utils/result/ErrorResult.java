package com.example.utils.result;

/**
 * 错误信息
 * @Author xiaoke
 * @Date 2022/12/5
 */
public enum ErrorResult {
    /*
     * 错误信息
     * */
    E_400("400", "请求处理异常，请稍后再试"),
    E_401("401","认证过期，请重新进行登录"),
    E_403("403","权限不足"),
    E_10000("10000","请求失败，请重新登录");

    private final String errorCode;

    private final String errorMsg;

    ErrorResult(String errorCode, String errorMsg) {
        this.errorCode = errorCode;
        this.errorMsg = errorMsg;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public String getErrorMsg() {
        return errorMsg;
    }
}
