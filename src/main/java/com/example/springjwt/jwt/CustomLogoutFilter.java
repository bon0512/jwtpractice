package com.example.springjwt.jwt;

import com.example.springjwt.service.RefreshTokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;

public class CustomLogoutFilter extends GenericFilterBean {

    private final RefreshTokenService refreshTokenService;
    private final String logoutPath;

    public CustomLogoutFilter(RefreshTokenService refreshTokenService, String logoutPath) {
        this.refreshTokenService = refreshTokenService;
        this.logoutPath = logoutPath;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
    }

    // 커스텀 로그아웃 처리 필터
    private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws IOException, ServletException {

        // 1. 요청 경로/메서드 체크
        String requestUri = request.getRequestURI();
        if (!requestUri.equals(logoutPath)) {
            filterChain.doFilter(request, response);
            return;
        }
        if (!request.getMethod().equals("POST")) {
            filterChain.doFilter(request, response);
            return;
        }

        // 2. Refresh Token 추출
        String refresh = refreshTokenService.extractRefreshToken(request.getCookies());
        if (refresh == null) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        // 3. Refresh Token 검증(DB + 만료 + category)
        try {
            refreshTokenService.validateRefresh(refresh);
        } catch (IllegalArgumentException e) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        // 4. DB에서 Refresh Token 삭제
        refreshTokenService.deleteByToken(refresh);

        // 5. 클라이언트 Refresh 쿠키 삭제 (maxAge = 0)
        Cookie cookie = new Cookie("refresh", null);
        cookie.setMaxAge(0);
        cookie.setPath("/");
        response.addCookie(cookie);

        // 6. 성공 응답
        response.setStatus(HttpServletResponse.SC_OK);
    }
}
