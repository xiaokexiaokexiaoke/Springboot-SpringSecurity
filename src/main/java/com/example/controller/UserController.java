package com.example.controller;

import com.alibaba.fastjson.JSONObject;
import com.example.service.UserService;
import com.example.utils.Results;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;

/**
 * @Author xiaoke
 * @Date 2022/12/5
 */
@RestController
@RequestMapping("/user")
public class UserController {


    @Resource
    private UserService userService;

    @PreAuthorize("hasAnyAuthority('space')")
    @GetMapping("/getUser")
    public JSONObject getUser(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return Results.successJson(authentication);
    }

    @PreAuthorize("hasAuthority('user:list')")
    @GetMapping("/getAllUser")
    public JSONObject getAllUser(){
        return userService.getAllUser();
    }
}
