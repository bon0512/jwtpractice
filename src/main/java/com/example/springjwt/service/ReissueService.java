package com.example.springjwt.service;

import com.example.springjwt.dto.ReissueTokens;
import com.example.springjwt.entity.RefreshTokenEntity;
import com.example.springjwt.jwt.JWTUtil;
import com.example.springjwt.repository.RefreshTokenRepository;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import org.springframework.stereotype.Service;

@Service
public class ReissueService {

    private final JWTUtil jwtUtil;
    private final RefreshTokenRepository refreshTokenRepository;

    public ReissueService(JWTUtil jwtUtil, RefreshTokenRepository refreshTokenRepository) {
        this.jwtUtil = jwtUtil;
        this.refreshTokenRepository = refreshTokenRepository;
    }


    //가져온 쿠키들 중 refresh 없으면 null
    public String extractRefreshToken(Cookie[] cookies) {
        if (cookies == null) return null;

        for (Cookie cookie : cookies) {
            if (cookie.getName().equals("refresh")) {
                return cookie.getValue();
            }
        }

        return null;
    }


    // ================================
    // 메인 로직
    // ================================
    public ReissueTokens reissueTokens(String oldRefreshToken) {

        // 1) 유효성 검증
        validateRefresh(oldRefreshToken);

        // 2) 사용자 정보 추출
        String username = jwtUtil.getUsername(oldRefreshToken);
        String role = jwtUtil.getRole(oldRefreshToken);

        // 3) refresh rotation → 새 refresh 저장 + old 삭제
        String newRefresh = rotateRefresh(username, oldRefreshToken, role);

        // 4) 새 access 생성
        String newAccess = createAccess(username, role);

        return new ReissueTokens(newAccess, newRefresh);
    }



    // ================================
    // Refresh 관련 함수들
    // ================================

    private void validateRefresh(String refreshToken) {
        if (refreshToken == null) {
            throw new IllegalArgumentException("refresh token null");
        }

        // DB 존재 여부
        if (!refreshTokenRepository.existsByToken(refreshToken)) {
            throw new IllegalArgumentException("refresh token not found in DB");
        }

        // 만료 체크
        try {
            jwtUtil.isExpired(refreshToken);
        } catch (ExpiredJwtException e) {
            throw new IllegalArgumentException("refresh token expired");
        }

        // category 검사
        if (!jwtUtil.getCategory(refreshToken).equals("refresh")) {
            throw new IllegalArgumentException("invalid refresh token");
        }
    }


    /** Refresh Rotation */
    private String rotateRefresh(String username, String oldRefreshToken, String role) {

        // old refresh 제거
        refreshTokenRepository.deleteByToken(oldRefreshToken);

        // 새 refresh 생성
        String newRefresh = createRefresh(username, role);

        // DB 저장
        saveRefresh(username, newRefresh);

        return newRefresh;
    }


    private String createRefresh(String username, String role) {

        return jwtUtil.createJwt("refresh", username, role, 1000L * 60 * 60 * 24 * 14);
    }

    private void saveRefresh(String username, String refreshToken) {
        Long expiry = System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 14);

        RefreshTokenEntity entity = RefreshTokenEntity.builder()
                .username(username)
                .token(refreshToken)
                .expiry(expiry)
                .build();

        refreshTokenRepository.save(entity);
    }



    // ================================
    // Access 관련 함수
    // ================================
    private String createAccess(String username, String role) {
        return jwtUtil.createJwt("access", username, role, 600000L); // 10분
    }



    // ================================
    // 쿠키 생성 함수
    // ================================
    public Cookie createCookie(String key, String value) {

        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(24 * 60 * 60);
        cookie.setHttpOnly(true);
        // cookie.setSecure(true);
        // cookie.setPath("/");

        return cookie;
    }
}

