package com.example.springjwt.service;

import com.example.springjwt.entity.RefreshTokenEntity;
import com.example.springjwt.entity.Role;
import com.example.springjwt.jwt.JWTUtil;
import com.example.springjwt.repository.RefreshTokenRepository;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import org.springframework.stereotype.Service;

@Service
public class RefreshTokenService {

    public static final long REFRESH_EXPIRY_MILLIS = 1000L * 60 * 60 * 24 * 14;

    private final RefreshTokenRepository refreshTokenRepository;
    private final JWTUtil jwtUtil;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository, JWTUtil jwtUtil) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.jwtUtil = jwtUtil;
    }

    // 저장 (기본 만료는 14일)
    public void saveRefreshToken(String username, String token) {
        saveRefreshToken(username, token, System.currentTimeMillis() + REFRESH_EXPIRY_MILLIS);
    }

    // 저장 (만료 직접 지정)
    public void saveRefreshToken(String username, String token, Long expiry) {
        refreshTokenRepository.deleteByUsername(username);

        RefreshTokenEntity refreshToken = RefreshTokenEntity.builder()
                .username(username)
                .token(token)
                .expiry(expiry)
                .build();

        refreshTokenRepository.save(refreshToken);
    }

    public RefreshTokenEntity getByUsername(String username) {
        return refreshTokenRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("can't find RefreshToken"));
    }

    public RefreshTokenEntity getByToken(String token) {
        return refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> new IllegalArgumentException("can't find RefreshToken"));
    }

    public void deleteUserToken(String username) {
        refreshTokenRepository.deleteByUsername(username);
    }

    public void deleteByToken(String token) {
        refreshTokenRepository.deleteByToken(token);
    }

    public String extractRefreshToken(Cookie[] cookies) {
        if (cookies == null) {
            return null;
        }

        for (Cookie cookie : cookies) {
            if ("refresh".equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }

    public void validateRefresh(String refreshToken) {

        if (refreshToken == null) {
            throw new IllegalArgumentException("refresh token null");
        }

        if (!refreshTokenRepository.existsByToken(refreshToken)) {
            throw new IllegalArgumentException("refresh token not found in DB");
        }

        try {
            jwtUtil.isExpired(refreshToken);
        } catch (ExpiredJwtException e) {
            throw new IllegalArgumentException("refresh token expired");
        }

        if (!"refresh".equals(jwtUtil.getCategory(refreshToken))) {
            throw new IllegalArgumentException("invalid refresh token");
        }
    }

    public String createRefreshToken(String username, Role role) {
        return jwtUtil.createJwt("refresh", username, role.name(), REFRESH_EXPIRY_MILLIS);
    }

    public long getRefreshExpiryMillis() {
        return REFRESH_EXPIRY_MILLIS;
    }

    public int getRefreshExpirySeconds() {
        return (int) (REFRESH_EXPIRY_MILLIS / 1000);
    }
}
