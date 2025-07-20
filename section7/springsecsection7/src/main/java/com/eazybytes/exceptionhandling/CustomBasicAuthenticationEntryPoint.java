package com.eazybytes.exceptionhandling;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;
import java.time.LocalDateTime;

/**
 * FilterSecurityInterceptor가 인증되지 않은 사용자의 요청을 받았을때
 * AuthenticationException을 던지고 AuthenticationEntryPoint가 호출된다.
 * 로그인페이지로 리다이렉트하거나 401 응답 보낸다.
 */
public class CustomBasicAuthenticationEntryPoint implements AuthenticationEntryPoint {

    // Spring Security에서 인증되지 않은 사용자가 보호된 리소스에 접근을 시도할 때 호출되는 메서드
    // commence 메서드를 오버라이드하여 기본 동작 대신 원하는 방식으로 인증 요구 로직을 커스터마이징할 수 있음.
    // 예를 들어, 단순한 401 응답 대신 특정 에러 페이지로 리다이렉트하거나, 커스텀 JSON 에러 메시지를 반환하는 등의 동작을 구현 가능
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
            throws IOException, ServletException {
        // Populate dynamic values
        LocalDateTime currentTimeStamp = LocalDateTime.now();
        String message = (authException != null && authException.getMessage() != null) ? authException.getMessage()
                : "Unauthorized";
        String path = request.getRequestURI();
        response.setHeader("eazybank-error-reason", "Authentication failed");
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType("application/json;charset=UTF-8");
        // Construct the JSON response
        String jsonResponse =
                String.format("{\"timestamp\": \"%s\", \"status\": %d, \"error\": \"%s\", \"message\": \"%s\", \"path\": \"%s\"}",
                        currentTimeStamp, HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase(),
                        message, path);
        response.getWriter().write(jsonResponse);
    }
}
