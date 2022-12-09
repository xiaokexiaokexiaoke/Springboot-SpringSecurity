package com.example.dao;

import com.alibaba.fastjson.JSONObject;
import com.example.entity.User;
import org.apache.ibatis.annotations.Param;

import java.util.List;


/**
 * @Author xiaoke
 * @Date 2022/11/25
 */
public interface UserDao {


    /**
     * 根据用户名查询用户
     * @param username 用户名
     * @return
     */
    User loadUserByUsername(String username);

    /**
     * 升级更新密码
     * @param username 用户名
     * @param password 密码
     * @return
     */
    Integer updatePassword(@Param("username") String username, @Param("password") String password);

    /**
     * 获取所有用户信息
     * @return 返回所有用户信息
     */
    List<JSONObject> getAllUser();
}
