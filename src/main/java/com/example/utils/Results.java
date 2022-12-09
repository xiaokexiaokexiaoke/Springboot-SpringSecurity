package com.example.utils;

import com.alibaba.fastjson.JSONObject;
import com.example.utils.result.ErrorResult;
import com.example.utils.result.SuccessResult;

/**
 * 返回数据处理
 * @Author xiaoke
 * @Date 2022/12/5
 */
public class Results {
    public static JSONObject successJson(){
        return successJson(new JSONObject());
    }

    public static JSONObject successJson(Object info){
        JSONObject data = new JSONObject();
        data.put("code",SuccessResult.SUCCESS_CODE);
        data.put("msg", SuccessResult.SUCCESS_MSG);
        data.put("info",info);
        return data;
    }

    public static JSONObject successLogout(){
        JSONObject data = new JSONObject();
        data.put("code",SuccessResult.SUCCESS_CODE);
        data.put("msg", SuccessResult.SUCCESS_LOGOUT);
        return data;
    }

    public static JSONObject successLogin(){
        JSONObject data = new JSONObject();
        data.put("code",SuccessResult.SUCCESS_CODE);
        data.put("msg", SuccessResult.SUCCESS_LOGIN);
        return data;
    }

    public static JSONObject errorJson(ErrorResult errorResult){
        JSONObject data = new JSONObject();
        data.put("code",errorResult.getErrorCode());
        data.put("msg",errorResult.getErrorMsg());
        data.put("info",new JSONObject());
        return data;
    }
}
