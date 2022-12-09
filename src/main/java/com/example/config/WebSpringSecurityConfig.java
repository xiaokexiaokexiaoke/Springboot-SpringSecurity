package com.example.config;

import com.example.config.securityConfig.authorization.MyAccessDecisionManager;
import com.example.config.securityConfig.authentication.MyAuthenticationFilter;
import com.example.config.securityConfig.authorization.MyFilterInvocationSecurityMetadataSource;
import com.example.config.securityConfig.handler.*;
import com.example.config.securityConfig.remember.MyPersistentTokenBasedRememberMeServices;
import com.example.service.MyUserDetailService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.InMemoryTokenRepositoryImpl;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.annotation.Resource;
import java.util.Arrays;
import java.util.UUID;

/**
 * 进行自定义的 SpringSecurity配置
 * @Author xiaoke
 * @Date 2022/12/5
 */

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
