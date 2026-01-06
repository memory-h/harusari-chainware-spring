package com.harusari.chainware.exception.auth.jwt;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

import static com.harusari.chainware.exception.auth.jwt.constant.SecurityError.FORBIDDEN;
import static com.harusari.chainware.exception.auth.jwt.constant.SecurityResponseConstants.JSON_UTF8;

@Component
public class RestAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException ex)
            throws IOException {
        response.setContentType(JSON_UTF8);
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);

        String jsonResponse = String.format("""
                {
                    "error": "%s",
                    "message": "%s"
                }
                """, FORBIDDEN.getError(), FORBIDDEN.getDefaultMessage());

        response.getWriter().write(jsonResponse);
    }

}