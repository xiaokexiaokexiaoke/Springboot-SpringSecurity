package com.example.service;

import com.alibaba.fastjson.JSONObject;
import com.example.dao.UserDao;
import com.example.utils.Results;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.List;

/**
 * @Author ldp
 * @Date 2022/12/9
 */
@Service
public class UserService {

    @Resource
    private UserDao userDao;

    public JSONObject getAllUser(){
        List<JSONObject> allUser = userDao.getAllUser();
        return Results.successJson(allUser);
    }
}
