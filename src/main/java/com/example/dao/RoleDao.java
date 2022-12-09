package com.example.dao;

import com.example.entity.Role;

import java.util.List;

/**
 * @Author xiaoke
 * @Date 2022/12/6
 */
public interface RoleDao {
    /**
     * 根据用户id查询角色
     * @param uid 用户id
     * @return
     */
    List<Role> getRolesByUid(Integer uid);


}
