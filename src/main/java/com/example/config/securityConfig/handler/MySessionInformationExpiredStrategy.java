package com.example.config.securityConfig.handler;

import com.example.utils.Results;
import com.example.utils.result.ErrorResult;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.web.session.SessionInformationExpiredEvent;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 自定义会话超时策略JSON数据
 * @Author xiaoke
 * @Date 2022/12/5
 */
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
