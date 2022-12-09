package com.example.entity;

import lombok.Data;

/**
 * @Author xiaoke
 * @Date 2022/12/6
 */
@Data
public class Permission {
    private Integer id;
    private String menuCode;
    private String menuName;
    private String permissionCode;
    private String permissionName;
    private String requestPath;
}
