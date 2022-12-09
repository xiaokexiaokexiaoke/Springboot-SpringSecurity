# Springboot-SpringSecurity
使用SpringSecurity完成前后端分离中后端认证授权的基础配置

##  **基于Springboot+SpringSecurity完成前后端认证授权的后端分享**


# 简介

针对于有一定的SpringSecurity基础的小伙伴进行学习，主要是实现相关的配置，进行相关配置的作用注解，不会对应相关具体原理实现做出讲解。

全部的代码获取（github）：[xiaokexiaokexiaoke/Springboot-SpringSecurity: 使用SpringSecurity完成前后端分离中后端认证授权的基础配置 (github.com)](https://github.com/xiaokexiaokexiaoke/Springboot-SpringSecurity)

如果觉得不错给个小星星(＾Ｕ＾)ノ~ＹＯ

# 主要功能

1.通过Springboot+SpringSecurity的整合完成后端的认证授权相关配置

2.使用RBAC，基于角色和资源权限设计就是: `用户<=>角色<=>权限<=>资源` 返回统称为用户的权限，主要通过权限、资源路径进行管理，也可以使用角色进行管理。

# 使用配置讲解

# 1.项目的基础搭建（相关依赖）

### 1）父项目springboot版本

```XML
 <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.6.13</version>
        <relativePath/> <!-- lookup parent from repository -->
    </parent>
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

### 2）数据库相关配置

```XML
 <dependency>
            <groupId>org.mybatis.spring.boot</groupId>
            <artifactId>mybatis-spring-boot-starter</artifactId>
            <version>2.1.4</version>
        </dependency>
        <dependency>
            <groupId>mysql</groupId>
            <artifactId>mysql-connector-java</artifactId>
            <version>8.0.23</version>
        </dependency>
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

### 3）springsecurity依赖配置

```XML
 <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
 <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-test</artifactId>
            <scope>test</scope>
        </dependency>
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

### 4）其他依赖

```XML
<!--对于实体类的简化-->
<dependency>
    <groupId>org.projectlombok</groupId>
     <artifactId>lombok</artifactId>
     <optional>true</optional>
</dependency>

<!--json数据的处理-->
<dependency>
            <groupId>com.alibaba</groupId>
            <artifactId>fastjson</artifactId>
            <version>1.2.83</version>
        </dependency>

<!--本机数据缓存-->
<dependency>
            <groupId>com.github.ben-manes.caffeine</groupId>
            <artifactId>caffeine</artifactId>
            <version>2.9.1</version>
        </dependency>
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)



# 2.数据库的创建

### 1）表结构

![img](https://img-blog.csdnimg.cn/973db0806f9f40eea871dd38f181443b.png)![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)编辑

###  2）建表语句

```sql
DROP TABLE IF EXISTS `permission`;
CREATE TABLE `permission`  (
  `id` int NOT NULL AUTO_INCREMENT COMMENT '权限id',
  `menu_name` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '菜单名称',
  `menu_code` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '菜单编号',
  `permission_name` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '权限名称',
  `permission_code` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '权限编号',
  `request_path` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '资源路径',
  PRIMARY KEY (`id`) USING BTREE
);

INSERT INTO `permission` VALUES (1, '用户管理', 'user', '添加', 'user:add', '/user/addUser');
INSERT INTO `permission` VALUES (2, '用户管理', 'user', '修改', 'user:update', '/user/updateUser');
INSERT INTO `permission` VALUES (3, '用户管理', 'user', '列表', 'user:list', '/user/getAllUser');
INSERT INTO `permission` VALUES (4, '用户管理', 'user', '删除', 'user:delete', '/user/deleteUser');
INSERT INTO `permission` VALUES (5, '个人信息', 'space', '个人', 'space', '/user/getUser');

DROP TABLE IF EXISTS `role`;
CREATE TABLE `role`  (
  `id` int NOT NULL AUTO_INCREMENT COMMENT '角色id',
  `name` varchar(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '角色名',
  `name_zh` varchar(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '角色中文名',
  PRIMARY KEY (`id`) USING BTREE
);


INSERT INTO `role` VALUES (1, 'ROLE_product', '商品管理员');
INSERT INTO `role` VALUES (2, 'ROLE_admin', '系统管理员');
INSERT INTO `role` VALUES (3, 'ROLE_user', '用户管理员');


DROP TABLE IF EXISTS `role_permission`;
CREATE TABLE `role_permission`  (
  `id` int NOT NULL AUTO_INCREMENT COMMENT '权限角色id',
  `permission_id` int NOT NULL COMMENT '权限id',
  `role_id` int NOT NULL COMMENT '角色id',
  PRIMARY KEY (`id`) USING BTREE
);


INSERT INTO `role_permission` VALUES (1, 1, 1);
INSERT INTO `role_permission` VALUES (2, 2, 1);
INSERT INTO `role_permission` VALUES (3, 3, 1);
INSERT INTO `role_permission` VALUES (4, 4, 1);
INSERT INTO `role_permission` VALUES (5, 1, 2);
INSERT INTO `role_permission` VALUES (6, 5, 1);
INSERT INTO `role_permission` VALUES (7, 5, 2);
INSERT INTO `role_permission` VALUES (8, 5, 3);


DROP TABLE IF EXISTS `user`;
CREATE TABLE `user`  (
  `id` int NOT NULL AUTO_INCREMENT COMMENT '用户id',
  `username` varchar(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '用户名',
  `password` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '密码',
  `nickname` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '昵称',
  `enabled` tinyint(1) NULL DEFAULT 1 COMMENT '是否可用，1可用',
  `accountNonExpired` tinyint(1) NULL DEFAULT 1 COMMENT '账号是否过期，1可用',
  `accountNonLocked` tinyint(1) NULL DEFAULT 1 COMMENT '账号是否锁定，1可用',
  `credentialsNonExpired` tinyint(1) NULL DEFAULT 1 COMMENT '凭证是否过期，1可用',
  PRIMARY KEY (`id`) USING BTREE
);

INSERT INTO `user` VALUES (1, 'root', '{noop}123', 'xiaoke', 1, 1, 1, 1);
INSERT INTO `user` VALUES (2, 'admin', '{noop}123', 'xixi', 1, 1, 1, 1);
INSERT INTO `user` VALUES (3, 'xiaoke', '{noop}123', 'xx', 1, 1, 1, 1);

DROP TABLE IF EXISTS `user_role`;
CREATE TABLE `user_role`  (
  `id` int NOT NULL AUTO_INCREMENT COMMENT '用户角色id',
  `user_id` int NULL DEFAULT NULL COMMENT '用户id',
  `role_id` int NULL DEFAULT NULL COMMENT '角色id',
  PRIMARY KEY (`id`) USING BTREE,
  INDEX `uid`(`user_id` ASC) USING BTREE,
  INDEX `rid`(`role_id` ASC) USING BTREE
);

INSERT INTO `user_role` VALUES (1, 1, 1);
INSERT INTO `user_role` VALUES (2, 1, 2);
INSERT INTO `user_role` VALUES (3, 2, 2);
INSERT INTO `user_role` VALUES (4, 3, 3);
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

# 3.项目模块管理

## 3.1基础配置模块

### 3.1.1返回数据封装

错误信息

```java
public enum ErrorResult {
    /*
     * 错误信息
     * */
    E_400("400", "请求处理异常，请稍后再试"),
    E_401("401","认证过期，请重新进行登录"),
    E_403("403","权限不足"),
    E_10000("10000","请求失败，请重新登录");

    private final String errorCode;

    private final String errorMsg;

    ErrorResult(String errorCode, String errorMsg) {
        this.errorCode = errorCode;
        this.errorMsg = errorMsg;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public String getErrorMsg() {
        return errorMsg;
    }
}
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

成功信息

```java
public class SuccessResult {
    public static final String SUCCESS_CODE = "200";
    public static final String SUCCESS_MSG = "";

    public static final String SUCCESS_LOGOUT = "注销成功";
    public static final String SUCCESS_LOGIN = "登录成功";
}
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

响应json数据

```java
public class Results {
    public static JSONObject successJson(){
        return successJson(new JSONObject());
    }

    public static JSONObject successJson(Object info){
        JSONObject data = new JSONObject();
        data.put("code",SuccessResult.SUCCESS_CODE);
        data.put("msg", SuccessResult.SUCCESS_MSG);
        data.put("info",info);
        return data;
    }

    public static JSONObject successLogout(){
        JSONObject data = new JSONObject();
        data.put("code",SuccessResult.SUCCESS_CODE);
        data.put("msg", SuccessResult.SUCCESS_LOGOUT);
        return data;
    }

    public static JSONObject successLogin(){
        JSONObject data = new JSONObject();
        data.put("code",SuccessResult.SUCCESS_CODE);
        data.put("msg", SuccessResult.SUCCESS_LOGIN);
        return data;
    }

    public static JSONObject errorJson(ErrorResult errorResult){
        JSONObject data = new JSONObject();
        data.put("code",errorResult.getErrorCode());
        data.put("msg",errorResult.getErrorMsg());
        data.put("info",new JSONObject());
        return data;
    }
}
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

## 3.2认证模块

### 3.2.1自定义UserDetails（对认证后返回的用户数据进行封装）

```java
@Data
public class User implements UserDetails {
    private Integer id;
    private String username;
    private String password;

    private String nickname;
    private Boolean enabled;
    private Boolean accountNonExpired;
    private Boolean accountNonLocked;
    private Boolean credentialsNonExpired;
    private List<Role> roles;
    private List<Permission> permissions;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        //用户具有的权限
        permissions.forEach(permission -> grantedAuthorities.add(new SimpleGrantedAuthority(permission.getPermissionCode())));
        //用户具有的角色
        roles.forEach(role->grantedAuthorities.add(new SimpleGrantedAuthority(role.getName())));
        return grantedAuthorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }
}
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

### 3.2.2自定义数据源（在进行认证时，使用数据库进行认证，不配置默认使用基于内存实现）

```java
@Service
public class MyUserDetailService implements UserDetailsService{

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

}
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

```java
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
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

```java
public interface RoleDao {
    /**
     * 根据用户id查询角色
     * @param uid 用户id
     * @return
     */
    List<Role> getRolesByUid(Integer uid);


}
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

```java
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
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

```XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.dao.PermissionDao">
    <select id="getPermissionByRid" resultType="com.example.entity.Permission">
        select distinct
        p.permission_code as permissionCode,
        p.permission_name as permissionName,
        p.id as permissionId,
        p.menu_code as menuCode,
        p.menu_name as menuName,
        p.request_path as requestPath
        from role_permission rp join permission p on p.id = rp.permission_id
        where role_id in
        <foreach collection="items" index="index" item="item" open="(" close=")" separator=",">
            #{item.id}
        </foreach>
    </select>
    <select id="getPermissionByUri" resultType="com.example.entity.Permission">
        select  permission_code as permissionCode,
                permission_name as permissionName,
                id as permissionId,
                menu_code as menuCode,
                menu_name as menuName,
                request_path as requestPath
        from permission
        where request_path = #{uri}
    </select>
</mapper>
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

```XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.dao.RoleDao">

    <!--查询指定行数据-->
    <select id="getRolesByUid" resultType="com.example.entity.Role">
        select r.id,
               r.name,
               r.name_zh nameZh
        from role r,
             user_role ur
        where r.id = ur.role_id
          and ur.user_id = #{uid}
    </select>

</mapper>
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

```XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.dao.UserDao">
    <!--查询单个-->
    <select id="loadUserByUsername" resultType="com.example.entity.User">
        select id,
               username,
               password,
               nickname,
               enabled,
               accountNonExpired,
               accountNonLocked,
               credentialsNonExpired
        from user
        where username = #{username}
    </select>

    <select id="getAllUser" resultType="com.alibaba.fastjson.JSONObject">
        select id,
               username,
               nickname,
               enabled,
               accountNonExpired,
               accountNonLocked,
               credentialsNonExpired
        from user
    </select>


    <update id="updatePassword">
        update `user` set password=#{password}
        where username=#{username}
    </update>
</mapper>
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

### 3.2.3重写UsernamePasswordAuthenticationFilter过滤器（默认使用表单格式进行数据的获取，前后端分离需要使用json格式数据，将其他数据获取部分进行重写）

```java
public class MyAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        //登录只处理post请求，可自行扩展
        if (!request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }
        if(request.getContentType().equalsIgnoreCase(MediaType.APPLICATION_JSON_VALUE)){
            try{
                //1.获取请求数据
                Map<String, String> userInfo = new ObjectMapper().readValue(request.getInputStream(), Map.class);
                String username = userInfo.get(getUsernameParameter());
                String password = userInfo.get(getPasswordParameter());
               
                //2.获取用户名 和密码认证
                UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);
                setDetails(request, authRequest);
                return this.getAuthenticationManager().authenticate(authRequest);
            }catch (IOException e){
                e.printStackTrace();
            }
        }
        return super.attemptAuthentication(request,response);
    }
}
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

### 3.2.4进行认证成功的json数据返回处理（前后端分离认证成功后使用json数据进行返回）

```java
public class MyAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        response.setContentType("application/json;charset=UTF-8");
        String s = new ObjectMapper().writeValueAsString(Results.successLogin());
        response.getWriter().println(s);
    }
}
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

### 3.2.5进行认证失败的json数据返回

```java
public class MyAuthenticationFailureHandler implements AuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        response.setContentType("application/json;charset=UTF-8");
        String s = new ObjectMapper().writeValueAsString(Results.errorJson(ErrorResult.E_10000));
        response.getWriter().println(s);
    }
}
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

### 3.2.6SpringSecurity核心配置文件

```java
@Configuration
public class WebSpringSecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     * 自定义的 UserDetailService
     * 用于连接数据库处理登录以及加密认证，更新密码
     */
    @Resource
    private MyUserDetailService myUserDetailService;

    @Resource
    private MyFilterInvocationSecurityMetadataSource myFilterInvocationSecurityMetadataSource;

    /**
     * @param auth 给自定义的认证管理器配置 UserDetailService
     * @throws Exception 异常
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(myUserDetailService);
    }

    /**
     * 将自定义的认证管理器暴露在IOC容器中，默认不暴露，无法在IOC中使用
     * @return 自定义的认证管理器
     * @throws Exception 异常
     */
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    /**
     * 解决处理前后端JSON数据接收问题
     * @return 自定义的用户认证管理器
     * @throws Exception 异常
     */
    @Bean
    public MyAuthenticationFilter myAuthenticationFilter() throws Exception{
        MyAuthenticationFilter myAuthenticationFilter = new MyAuthenticationFilter();
        myAuthenticationFilter.setFilterProcessesUrl("/login");
        myAuthenticationFilter.setUsernameParameter("username");
        myAuthenticationFilter.setPasswordParameter("password");
        myAuthenticationFilter.setAuthenticationManager(authenticationManager());
        myAuthenticationFilter.setAuthenticationSuccessHandler(new MyAuthenticationSuccessHandler());
        myAuthenticationFilter.setAuthenticationFailureHandler(new MyAuthenticationFailureHandler());
        return myAuthenticationFilter;
    }



    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                //配置请求认证
                .anyRequest().authenticated()
                //配置表单认证
                .and().formLogin()
                //配置跨站请求攻击
                .and().csrf()
                .disable()
        //使用自定义处理JSON数据的认证过滤器替代默认的认证过滤器
        http.addFilterAt(myAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
    }
}
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

## 3.3登出模块

### 3.3.1登出成功的json数据返回

```java
public class MyLogoutSuccessHandler implements LogoutSuccessHandler {
    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        response.setContentType("application/json;charset=UTF-8");
        String s = new ObjectMapper().writeValueAsString(Results.successLogout());
        response.getWriter().println(s);
    }
}
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

### 3.3.2SpringSecurity核心配置

```java
  @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                //配置请求认证
                .anyRequest().authenticated()
                //配置表单认证
                .and().formLogin()
                .and().logout()
                .permitAll()
                //那些请求按登出处理
                .logoutRequestMatcher(new OrRequestMatcher(
                        new AntPathRequestMatcher("/logout1","GET"),
                        new AntPathRequestMatcher("/logout","GET")
                ))
                .logoutSuccessHandler(new MyLogoutSuccessHandler())
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                //配置跨站请求攻击
                .and().csrf()
                .disable()
        //使用自定义处理JSON数据的认证过滤器替代默认的认证过滤器
        http.addFilterAt(myAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
    }
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)



## 3.4密码加密更新模块

问题分析：什么时候会开启密码加密功能

默认的加密方式是DelegatingPasswordEncoder会根据数据库密码大括号中的类型进行匹配，如果修改使用具体加密方式则不会进行匹配，进行直接加密比对

什么时候进行密码更新 ：

前提：数据库密码与现有密码的加密方式不一致

1）实现UserDetailsPasswordService进行更新密码的方法重写，这种方式会默认使用DelegatingPasswordEncoder中的更新策略进行更新，默认使用（BCrypt）

2）配置密码更新 （在SpringSecurity核心配置文件中配置加密方式的bean对象）    

```java
 /**
     * 如果在IOC容器中配置了 PasswordEncoder，则会自动加载配置的加密方式
     * 自动配置数据库没有前面的{noop}这种加密方式,会直接根据固定方式进行密码比对，以及密码更新
     * 否则使用默认的加密方式进行密码更新 DelegatingPasswordEncoder
     * 默认配置会根据数据密码前面{noop}进行相应密码比对，更新会根据框架默认进行更新（目前为 BCryptPasswordEncoder）
     * 推荐不配置，使用默认密码更新
     * @return 密码加密方式 BCryptPasswordEncoder
     */
@Bean
    public PasswordEncoder BcryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

### 3.4.1实现UserDetailsPasswordService，进行数据库的密码更新

```java
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
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

## 3.5记住我功能

问题分析：

记住我功能主要是通过用户在前端选择记住我功能后，在登录时向后端发送一个参数

remember-me，内容填写可以进行自定义修改，然后对该用户生成一个记住我信息的cookie对象令牌，如果以后用户登录信息过期，但是带着这个cookie对象的话，则会通过该cookie对象进行自动登录。

### 3.5.1获取remember-me参数使用json格式

```java
public class MyAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        //登录只处理post请求，可自行扩展
        if (!request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }
        if(request.getContentType().equalsIgnoreCase(MediaType.APPLICATION_JSON_VALUE)){
            try{
                //1.获取请求数据
                Map<String, String> userInfo = new ObjectMapper().readValue(request.getInputStream(), Map.class);
                String username = userInfo.get(getUsernameParameter());
                String password = userInfo.get(getPasswordParameter());
                String rememberValue = userInfo.get(AbstractRememberMeServices.DEFAULT_PARAMETER);
                //2.判断是否有remember-me
                if (!ObjectUtils.isEmpty(rememberValue)) {
                    request.setAttribute(AbstractRememberMeServices.DEFAULT_PARAMETER, rememberValue);
                }else {
                    //防止后续进行该参数获取时出现空指针异常
                    request.setAttribute(AbstractRememberMeServices.DEFAULT_PARAMETER, "not have");
                }
                //3.获取用户名 和密码认证
                UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);
                setDetails(request, authRequest);
                return this.getAuthenticationManager().authenticate(authRequest);
            }catch (IOException e){
                e.printStackTrace();
            }
        }
        return super.attemptAuthentication(request,response);
    }
}
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

### 3.5.2开启记住我功能

```java
 /**
     * 使用令牌保存在本机缓存中
     * @return RememberMeServices 自定义的记住我服务
     */
    @Bean
    public RememberMeServices rememberMeServices() {
        return new MyPersistentTokenBasedRememberMeServices(UUID.randomUUID().toString(), myUserDetailService, new InMemoryTokenRepositoryImpl());
    }

  @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                //配置请求认证
                .anyRequest().authenticated()
                //配置表单认证
                .and().formLogin()
                .and().logout()
                .permitAll()
                //那些请求按登出处理
                .logoutRequestMatcher(new OrRequestMatcher(
                        new AntPathRequestMatcher("/logout1","GET"),
                        new AntPathRequestMatcher("/logout","GET")
                ))
                .logoutSuccessHandler(new MyLogoutSuccessHandler())
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                 //配置记住我功能
                .and().rememberMe()
                .rememberMeServices(rememberMeServices())
                //配置跨站请求攻击
                .and().csrf()
                .disable()
        //使用自定义处理JSON数据的认证过滤器替代默认的认证过滤器
        http.addFilterAt(myAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
    }
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

## 3.6会话管理

会话并发管理就是指在当前系统中，同一个用户可以同时创建多少个会话，如果一个设备对应一个会话，那么也可以简单理解为同一个用户可以同时在多少台设备上进行登录。默认情况下，同一用户在多少台设备上登录并没有限制，不过开发者可以在 Spring Security 中对此进行配置。

### 3.6.1会话过期策略

```java
public class MySessionInformationExpiredStrategy implements SessionInformationExpiredStrategy {
    @Override
    public void onExpiredSessionDetected(SessionInformationExpiredEvent event) throws IOException, ServletException {
        HttpServletResponse response = event.getResponse();
        response.setContentType("application/json;charset=UTF-8");
        String s = new ObjectMapper().writeValueAsString(Results.errorJson(ErrorResult.E_401));
        response.getWriter().println(s);
        response.flushBuffer();
    }
}
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

### 3.6.2会话配置

```java
/**
     * @return 监听会话
     */
    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }
@Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                //配置请求认证
                .anyRequest().authenticated()
                //配置表单认证
                .and().formLogin()
                .and().logout()
                .permitAll()
                //那些请求按登出处理
                .logoutRequestMatcher(new OrRequestMatcher(
                        new AntPathRequestMatcher("/logout1","GET"),
                        new AntPathRequestMatcher("/logout","GET")
                ))
                .logoutSuccessHandler(new MyLogoutSuccessHandler())
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                 //配置记住我功能
                .and().rememberMe()
                .rememberMeServices(rememberMeServices())
                //配置跨站请求攻击
                .and().csrf()
                .disable()
                //配置会话管理，该会话管理配置保存在本机中
                //如果需要session共享，引入spring-session-data-redis依赖，进行redis配置共享
                .sessionManagement()
                .maximumSessions(1)
                .expiredSessionStrategy(new MySessionInformationExpiredStrategy());
        //使用自定义处理JSON数据的认证过滤器替代默认的认证过滤器
        http.addFilterAt(myAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
    }
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

## 3.7跨域管理

跨域请求配置

```java
 /**
     * @return 跨域请求配置
     */
    CorsConfigurationSource configurationSource() {
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowedHeaders(Arrays.asList("*"));
        corsConfiguration.setAllowedMethods(Arrays.asList("*"));
        corsConfiguration.setAllowedOrigins(Arrays.asList("*"));
        corsConfiguration.setMaxAge(3600L);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfiguration);
        return source;
    }
@Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                //配置请求认证
                .anyRequest().authenticated()
                //配置表单认证
                .and().formLogin()
                .and().logout()
                .permitAll()
                //那些请求按登出处理
                .logoutRequestMatcher(new OrRequestMatcher(
                        new AntPathRequestMatcher("/logout1","GET"),
                        new AntPathRequestMatcher("/logout","GET")
                ))
                .logoutSuccessHandler(new MyLogoutSuccessHandler())
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                 //配置记住我功能
                .and().rememberMe()
                .rememberMeServices(rememberMeServices())
                 //配置跨域请求
                .and().cors()
                .configurationSource(configurationSource())
                //配置跨站请求攻击
                .and().csrf()
                .disable()
                //配置会话管理，该会话管理配置保存在本机中
                //如果需要session共享，引入spring-session-data-redis依赖，进行redis配置共享
                .sessionManagement()
                .maximumSessions(1)
                .expiredSessionStrategy(new MySessionInformationExpiredStrategy());
        //使用自定义处理JSON数据的认证过滤器替代默认的认证过滤器
        http.addFilterAt(myAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
    }
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

## 3.8异常处理

主要将处理返回改成前后端分离json数据返回

### 3.8.1认证异常处理

```java
public class MyAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        String s = new ObjectMapper().writeValueAsString(Results.errorJson(ErrorResult.E_10000));
        response.getWriter().println(s);
    }
}
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

### 3.8.2授权异常处理

```java
public class MyAccessDeniedHandler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(HttpStatus.FORBIDDEN.value());
        String s = new ObjectMapper().writeValueAsString(Results.errorJson(ErrorResult.E_403));
        response.getWriter().println(s);
    }
}
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

### 3.8.3异常配置

```java
@Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                //配置请求认证
                .anyRequest().authenticated()
                //配置表单认证
                .and().formLogin()
                .and().logout()
                .permitAll()
                //那些请求按登出处理
                .logoutRequestMatcher(new OrRequestMatcher(
                        new AntPathRequestMatcher("/logout1","GET"),
                        new AntPathRequestMatcher("/logout","GET")
                ))
                .logoutSuccessHandler(new MyLogoutSuccessHandler())
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                 //配置记住我功能
                .and().rememberMe()
                .rememberMeServices(rememberMeServices())
                //配置异常处理
                .and()
                .exceptionHandling()
                .authenticationEntryPoint(new MyAuthenticationEntryPoint())
                .accessDeniedHandler(new MyAccessDeniedHandler())
                 //配置跨域请求
                .and().cors()
                .configurationSource(configurationSource())
                //配置跨站请求攻击
                .and().csrf()
                .disable()
                //配置会话管理，该会话管理配置保存在本机中
                //如果需要session共享，引入spring-session-data-redis依赖，进行redis配置共享
                .sessionManagement()
                .maximumSessions(1)
                .expiredSessionStrategy(new MySessionInformationExpiredStrategy());
        //使用自定义处理JSON数据的认证过滤器替代默认的认证过滤器
        http.addFilterAt(myAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
    }
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

### 3.9授权处理

### 3.9.1基于过滤器的权限管理

1）安全数据源（通过请求的uri去数据库查询访问该uri所需要的权限）

```java
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
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

2）决策管理器（将uri对应的权限与用户的权限进行比对，如果相同则放行）

```java
@Component
public class MyAccessDecisionManager implements AccessDecisionManager {
    @Override
    public void decide(Authentication authentication, Object object, Collection<ConfigAttribute> configAttributes) throws AccessDeniedException, InsufficientAuthenticationException {
        Iterator<ConfigAttribute> iterator = configAttributes.iterator();
        //遍历每一个请求该路径需要的权限，拥有其中一个即可
        while (iterator.hasNext()) {
            ConfigAttribute ca = iterator.next();
            //当前请求需要的权限
            String needPermissionCode = ca.getAttribute();
            //当前用户所具有的权限
            Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
            for (GrantedAuthority authority : authorities) {
                if (authority.getAuthority().equals(needPermissionCode)) {
                    return;
                }
            }
        }
        throw new AccessDeniedException("权限不足!");
    }

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }
}
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

3）基于过滤器的配置

```java
    @Resource
    private MyFilterInvocationSecurityMetadataSource myFilterInvocationSecurityMetadataSource;

    @Resource
    private MyAccessDecisionManager myAccessDecisionManager;

 @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                //配置请求认证
                //.mvcMatchers("/user/getUser").authenticated()
                .anyRequest().authenticated()
                //配置权限管理
                //1.使用路径匹配(过滤器方式) withObjectPostProcessor配置(使用这种方式将方法上面权限注解注释)
                //2.可以使用aop，在方法上面加注解 (使用这种方式将下面的withObjectPostProcessor配置注解)
                //两种不要同时使用，会进行两次权限判断，消耗性能
                .withObjectPostProcessor(new ObjectPostProcessor<FilterSecurityInterceptor>() {
                    @Override
                    public <O extends FilterSecurityInterceptor> O postProcess(O object) {
                        //配置安全数据源
                        object.setSecurityMetadataSource(myFilterInvocationSecurityMetadataSource);
                        //配置决策管理器
                        object.setAccessDecisionManager(myAccessDecisionManager);
                        //拒绝公共调用,设置为true，那么在查询该路径的权限时，不能为空
                        //object.setRejectPublicInvocations(true);
                        return object;
                    }
                })
                //配置表单认证
                .and().formLogin()
                //配置登出处理
                .and().logout()
                .permitAll()
                //那些请求按登出处理
                .logoutRequestMatcher(new OrRequestMatcher(
                        new AntPathRequestMatcher("/logout1","GET"),
                        new AntPathRequestMatcher("/logout","GET")
                ))
                .logoutSuccessHandler(new MyLogoutSuccessHandler())
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                //配置记住我功能
                .and().rememberMe()
                .rememberMeServices(rememberMeServices())
                //配置异常处理
                .and()
                .exceptionHandling()
                .authenticationEntryPoint(new MyAuthenticationEntryPoint())
                .accessDeniedHandler(new MyAccessDeniedHandler())
                //配置跨域请求
                .and().cors()
                .configurationSource(configurationSource())
                //配置跨站请求攻击
                .and().csrf()
                .disable()
                //配置会话管理，该会话管理配置保存在本机中
                //如果需要session共享，引入spring-session-data-redis依赖，进行redis配置共享
                .sessionManagement()
                .maximumSessions(1)
                .expiredSessionStrategy(new MySessionInformationExpiredStrategy());
        //使用自定义处理JSON数据的认证过滤器替代默认的认证过滤器
        http.addFilterAt(myAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
    }
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)



### 3.9.2基于aop的权限管理

在方法上面加上对应方法所需要的角色或者权限即可（角色需要加ROLE_前缀，权限不需要）

1）需要开启全局方法权限注解

```java
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled=true,securedEnabled=true, jsr250Enabled=true)
public class WebSpringSecurityConfig extends WebSecurityConfigurerAdapter {
    ...
}
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

2)使用相应注解

```java
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
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

3）配置文件

```java
 @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                //配置请求认证
                .anyRequest().authenticated()
                //配置表单认证
                .and().formLogin()
                //配置登出处理
                .and().logout()
                .permitAll()
                //那些请求按登出处理
                .logoutRequestMatcher(new OrRequestMatcher(
                        new AntPathRequestMatcher("/logout1","GET"),
                        new AntPathRequestMatcher("/logout","GET")
                ))
                .logoutSuccessHandler(new MyLogoutSuccessHandler())
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                //配置记住我功能
                .and().rememberMe()
                .rememberMeServices(rememberMeServices())
                //配置异常处理
                .and()
                .exceptionHandling()
                .authenticationEntryPoint(new MyAuthenticationEntryPoint())
                .accessDeniedHandler(new MyAccessDeniedHandler())
                //配置跨域请求
                .and().cors()
                .configurationSource(configurationSource())
                //配置跨站请求攻击
                .and().csrf()
                .disable()
                //配置会话管理，该会话管理配置保存在本机中
                //如果需要session共享，引入spring-session-data-redis依赖，进行redis配置共享
                .sessionManagement()
                .maximumSessions(1)
                .expiredSessionStrategy(new MySessionInformationExpiredStrategy());
        //使用自定义处理JSON数据的认证过滤器替代默认的认证过滤器
        http.addFilterAt(myAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
    }
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)



## 3.10最终的SpringSecurity核心配置文件

```java
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled=true,securedEnabled=true, jsr250Enabled=true)
public class WebSpringSecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     * 自定义的 UserDetailService
     * 用于连接数据库处理登录以及加密认证，更新密码
     */
    @Resource
    private MyUserDetailService myUserDetailService;

    @Resource
    private MyFilterInvocationSecurityMetadataSource myFilterInvocationSecurityMetadataSource;

    @Resource
    private MyAccessDecisionManager myAccessDecisionManager;

    /**
     * 如果在IOC容器中配置了 PasswordEncoder，则会自动加载配置的加密方式
     * 自动配置数据库没有前面的{noop}这种加密方式,会直接根据固定方式进行密码比对，以及密码更新
     * 否则使用默认的加密方式进行密码更新 DelegatingPasswordEncoder
     * 默认配置会根据数据密码前面{noop}进行相应密码比对，更新会根据框架默认进行更新（目前为 BCryptPasswordEncoder）
     * 推荐不配置，使用默认密码更新
     * @return 密码加密方式 BCryptPasswordEncoder
     */
    //@Bean
    public PasswordEncoder BcryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * @param auth 给自定义的认证管理器配置 UserDetailService
     * @throws Exception 异常
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(myUserDetailService);
    }

    /**
     * 将自定义的认证管理器暴露在IOC容器中，默认不暴露，无法在IOC中使用
     * @return 自定义的认证管理器
     * @throws Exception 异常
     */
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    /**
     * 使用令牌保存在本机缓存中
     * @return RememberMeServices 自定义的记住我服务
     */
    @Bean
    public RememberMeServices rememberMeServices() {
        return new MyPersistentTokenBasedRememberMeServices(UUID.randomUUID().toString(), myUserDetailService, new InMemoryTokenRepositoryImpl());
    }

    /**
     * 解决处理前后端JSON数据接收问题
     * @return 自定义的用户认证管理器
     * @throws Exception 异常
     */
    @Bean
    public MyAuthenticationFilter myAuthenticationFilter() throws Exception{
        MyAuthenticationFilter myAuthenticationFilter = new MyAuthenticationFilter();
        myAuthenticationFilter.setFilterProcessesUrl("/login");
        myAuthenticationFilter.setUsernameParameter("username");
        myAuthenticationFilter.setPasswordParameter("password");
        myAuthenticationFilter.setAuthenticationManager(authenticationManager());
        myAuthenticationFilter.setRememberMeServices(rememberMeServices());
        myAuthenticationFilter.setAuthenticationSuccessHandler(new MyAuthenticationSuccessHandler());
        myAuthenticationFilter.setAuthenticationFailureHandler(new MyAuthenticationFailureHandler());
        return myAuthenticationFilter;
    }

    /**
     * @return 监听会话
     */
    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    /**
     * @return 跨域请求配置
     */
    CorsConfigurationSource configurationSource() {
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowedHeaders(Arrays.asList("*"));
        corsConfiguration.setAllowedMethods(Arrays.asList("*"));
        corsConfiguration.setAllowedOrigins(Arrays.asList("*"));
        corsConfiguration.setMaxAge(3600L);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfiguration);
        return source;
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                //配置请求认证
                //.mvcMatchers("/user/getUser").authenticated()
                .anyRequest().authenticated()
                //配置权限管理
                //1.使用路径匹配(过滤器方式) withObjectPostProcessor配置(使用这种方式将方法上面权限注解注释)
                //2.可以使用aop，在方法上面加注解 (使用这种方式将下面的withObjectPostProcessor配置注解)
                //两种不要同时使用，会进行两次权限判断，消耗性能
                .withObjectPostProcessor(new ObjectPostProcessor<FilterSecurityInterceptor>() {
                    @Override
                    public <O extends FilterSecurityInterceptor> O postProcess(O object) {
                        //配置安全数据源
                        object.setSecurityMetadataSource(myFilterInvocationSecurityMetadataSource);
                        //配置决策管理器
                        object.setAccessDecisionManager(myAccessDecisionManager);
                        //拒绝公共调用,设置为true，那么在查询该路径的权限时，不能为空
                        //object.setRejectPublicInvocations(true);
                        return object;
                    }
                })
                //配置表单认证
                .and().formLogin()
                //配置登出处理
                .and().logout()
                .permitAll()
                //那些请求按登出处理
                .logoutRequestMatcher(new OrRequestMatcher(
                        new AntPathRequestMatcher("/logout1","GET"),
                        new AntPathRequestMatcher("/logout","GET")
                ))
                .logoutSuccessHandler(new MyLogoutSuccessHandler())
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                //配置记住我功能
                .and().rememberMe()
                .rememberMeServices(rememberMeServices())
                //配置异常处理
                .and()
                .exceptionHandling()
                .authenticationEntryPoint(new MyAuthenticationEntryPoint())
                .accessDeniedHandler(new MyAccessDeniedHandler())
                //配置跨域请求
                .and().cors()
                .configurationSource(configurationSource())
                //配置跨站请求攻击
                .and().csrf()
                .disable()
                //配置会话管理，该会话管理配置保存在本机中
                //如果需要session共享，引入spring-session-data-redis依赖，进行redis配置共享
                .sessionManagement()
                .maximumSessions(1)
                .expiredSessionStrategy(new MySessionInformationExpiredStrategy());
        //使用自定义处理JSON数据的认证过滤器替代默认的认证过滤器
        http.addFilterAt(myAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
    }
}
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)
