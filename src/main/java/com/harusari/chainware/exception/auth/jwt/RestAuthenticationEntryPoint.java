package com.harusari.chainware.exception.auth.jwt;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

import static com.harusari.chainware.exception.auth.jwt.constant.SecurityError.UNAUTHORIZED;
import static com.harusari.chainware.exception.auth.jwt.constant.SecurityResponseConstants.JSON_UTF8;

@Component
public class RestAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(
            HttpServletRequest request, HttpServletResponse response, AuthenticationException authException
    ) throws IOException {
        response.setContentType(JSON_UTF8);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // 401, 인증 실패

        String jsonResponse = String.format("""
                {
                    "error": "%s",
                    "message": "%s"
                }
                """, UNAUTHORIZED.getError(), UNAUTHORIZED.getDefaultMessage());

        response.getWriter().write(jsonResponse);
    }

}