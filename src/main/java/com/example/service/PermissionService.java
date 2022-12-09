package com.example.service;

import com.example.dao.PermissionDao;
import com.example.entity.Permission;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.List;

/**
 * @Author ldp
 * @Date 2022/12/6
 */
@Service
public class PermissionService {

    @Resource
    private PermissionDao permissionDao;


    public List<Permission> getPermissionByUri(String uri){
        return permissionDao.getPermissionByUri(uri);
    }
}
