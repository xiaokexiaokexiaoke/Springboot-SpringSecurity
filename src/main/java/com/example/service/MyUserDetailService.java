package com.example.service;

import com.example.dao.PermissionDao;
import com.example.dao.RoleDao;
import com.example.dao.UserDao;
import com.example.entity.Permission;
import com.example.entity.Role;
import com.example.entity.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.util.ObjectUtils;

import javax.annotation.Resource;
import java.util.List;

/**
 * 自定义UserDetailService,UserDetailsPasswordService
 * 1.从数据库中进行认证处理
 * 2.进行密码的自动更新
 * @Author xiaoke
 * @Date 2022/12/5
 */
@Service
public class MyUserDetailService implements UserDetailsService, UserDetailsPasswordService {

    @Resource
    private UserDao userDao;

    @Resource
    private RoleDao roleDao;

    @Resource
    private PermissionDao permissionDao;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //从数据中查询该用户，这部分可以进行缓存，或者配置布隆过滤器防止恶意请求
        User user = userDao.loadUserByUsername(username);
        if(ObjectUtils.isEmpty(user)) {
            throw new RuntimeException("用户不存在");
        }
        //获取用户的角色信息
        List<Role> rolesByUid = roleDao.getRolesByUid(user.getId());
        //获取用户的所有角色对应权限
        List<Permission> permissionByRid = permissionDao.getPermissionByRid(rolesByUid);
        user.setRoles(rolesByUid);
        user.setPermissions(permissionByRid);
        return user;
    }

    @Override
    public UserDetails updatePassword(UserDetails user, String newPassword) {
        //进行数据库密码更新
        Integer result = userDao.updatePassword(user.getUsername(), newPassword);
        if (result == 1) {
            ((User) user).setPassword(newPassword);
        }
        return user;
    }
}
