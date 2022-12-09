package com.example.config.cacheConfig;

import com.example.entity.Permission;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * 可进行缓存管理
 * @author xioake
 */
@Configuration
@EnableCaching
public class CacheConfig {
    /**
     * permission放在本地缓存中
     * 可以改造为放在redis中
     */
    @Bean("permissionCacheManager")
    public Cache<String, List<Permission>> caffeineCache() {
        return Caffeine.newBuilder()
                // 设置最后一次访问后经过固定时间过期.
                .expireAfterAccess(1L, TimeUnit.DAYS)
                // 初始的缓存空间大小
                .initialCapacity(100)
                // 缓存的最大条数
                .maximumSize(1000)
                .build();
    }
}
