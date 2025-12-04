package com.example.springjwt.service;

import com.example.springjwt.dto.ReissueTokens;
import com.example.springjwt.entity.Role;
import com.example.springjwt.jwt.JWTUtil;
import jakarta.servlet.http.Cookie;
import org.springframework.stereotype.Service;

@Service
public class ReissueService {

    private final JWTUtil jwtUtil;
    private final RefreshTokenService refreshTokenService;

    public ReissueService(JWTUtil jwtUtil, RefreshTokenService refreshTokenService) {
        this.jwtUtil = jwtUtil;
        this.refreshTokenService = refreshTokenService;
    }

    public String extractRefreshToken(Cookie[] cookies) {
        return refreshTokenService.extractRefreshToken(cookies);
    }

    public ReissueTokens reissueTokens(String oldRefreshToken) {

        refreshTokenService.validateRefresh(oldRefreshToken);

        String username = jwtUtil.getUsername(oldRefreshToken);
        Role role = Role.valueOf(jwtUtil.getRole(oldRefreshToken));

        String newRefresh = rotateRefresh(username, oldRefreshToken, role);
        String newAccess = createAccess(username, role);

        return new ReissueTokens(newAccess, newRefresh);
    }

    private String rotateRefresh(String username, String oldRefreshToken, Role role) {

        refreshTokenService.deleteByToken(oldRefreshToken);

        String newRefresh = refreshTokenService.createRefreshToken(username, role);
        refreshTokenService.saveRefreshToken(username, newRefresh);

        return newRefresh;
    }

    private String createAccess(String username, Role role) {
        return jwtUtil.createJwt("access", username, role.name(), 600000L); // 10분
    }

    public Cookie createCookie(String key, String value) {

        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(refreshTokenService.getRefreshExpirySeconds());
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        // cookie.setSecure(true);

        return cookie;
    }
}
