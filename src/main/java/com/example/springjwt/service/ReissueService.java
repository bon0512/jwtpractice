package com.example.springjwt.service;

import com.example.springjwt.dto.ReissueTokens;
import com.example.springjwt.jwt.JWTUtil;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import org.springframework.stereotype.Service;

@Service
public class ReissueService {

    private final JWTUtil jwtUtil;

    public ReissueService(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    // refresh 쿠키에서 토큰 꺼내기
    public String extractRefreshToken(Cookie[] cookies) {
        if (cookies == null) return null;

        for (Cookie cookie : cookies) {
            if (cookie.getName().equals("refresh")) {
                return cookie.getValue();
            }
        }

        return null;
    }

    // refresh 검증하고 새 access 토큰 발급
    public ReissueTokens reissueTokens(String refreshToken) {

        validateRefresh(refreshToken);

        String username = jwtUtil.getUsername(refreshToken);
        String role = jwtUtil.getRole(refreshToken);

        String newAccess = jwtUtil.createJwt("access", username, role, 600000L);
        String newRefresh = jwtUtil.createJwt("refresh", username, role, 1000L * 60 * 60 * 24 * 14); // 14일

        return new ReissueTokens(newAccess, newRefresh);
    }

    private void validateRefresh(String refreshToken) {
        if (refreshToken == null) {
            throw new IllegalArgumentException("refresh token null");
        }

        try {
            jwtUtil.isExpired(refreshToken);
        } catch (ExpiredJwtException e) {
            throw new IllegalArgumentException("refresh token expired");
        }

        if (!jwtUtil.getCategory(refreshToken).equals("refresh")) {
            throw new IllegalArgumentException("invalid refresh token");
        }
    }



    public Cookie createCookie(String key, String value) {

        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(24*60*60);
        //cookie.setSecure(true);
        //cookie.setPath("/");
        cookie.setHttpOnly(true);

        return cookie;
    }
}
