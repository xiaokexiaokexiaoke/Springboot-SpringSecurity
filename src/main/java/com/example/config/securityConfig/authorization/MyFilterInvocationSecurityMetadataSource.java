package com.example.config.securityConfig.authorization;

import com.example.entity.Permission;
import com.example.service.PermissionService;
import com.github.benmanes.caffeine.cache.Cache;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import javax.annotation.Resource;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * 通过过滤器的方式实现授权操作
 * 每次通过查询数据库来判断改用户是否有相应的权限
 * @Author xiaoke
 * @Date 2022/12/6
 */
@Component
public class MyFilterInvocationSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {

    AntPathMatcher antPathMatcher = new AntPathMatcher();

    @Resource(name = "permissionCacheManager")
    private Cache<String,List<Permission>> permissionCache;
    @Resource
    private PermissionService permissionService;

    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
        //获取请求资源uri
        String requestURI = ((FilterInvocation) object).getRequest().getRequestURI();
        //获取请求该资源需要的权限(有其中一个就可以访问)
        //因为这个一般不会进行修改，又会进行频繁的查询，所以放入缓存中
        List<Permission> permissions = permissionCache.getIfPresent(requestURI);
        //如果缓存中没有，从数据库查询，放入缓存中
        if(permissions == null){
            permissions = permissionService.getPermissionByUri(requestURI);
            if (permissions == null || permissions.size() == 0){
                //没有权限则可以直接通过
                return null;
            }
            permissionCache.put(requestURI,permissions);
        }
        String[] permissionsCode = permissions.stream().map(r -> r.getPermissionCode()).toArray(String[]::new);
        return SecurityConfig.createList(permissionsCode);
    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return null;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz);
    }
}
