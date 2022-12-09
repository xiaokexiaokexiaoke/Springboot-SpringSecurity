package com.example.dao;

import com.example.entity.Permission;
import com.example.entity.Role;
import org.apache.ibatis.annotations.Param;

import java.util.List;

/**
 * @Author xiaoke
 * @Date 2022/12/6
 */
public interface PermissionDao {
    /**
     * 根据角色查询权限
     * @param items 角色id
     * @return 权限信息
     */
    List<Permission> getPermissionByRid(@Param("items") List<Role> items);

    /**
     * 通过资源路径返回需要的权限
     * @param uri 请求资源路径
     * @return 需要的权限
     */
    List<Permission> getPermissionByUri(@Param("uri") String uri);
}
