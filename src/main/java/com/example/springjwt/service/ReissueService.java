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

    // 쿠키 배열에서 refreshToken 값을 추출
    public String extractRefreshToken(Cookie[] cookies) {
        return refreshTokenService.extractRefreshToken(cookies);
    }

    // 기존 RefreshToken 검증 후 새 Access / Refresh 토큰 재발급
    public ReissueTokens reissueTokens(String oldRefreshToken) {

        refreshTokenService.validateRefresh(oldRefreshToken);

        String username = jwtUtil.getUsername(oldRefreshToken);
        Role role = Role.valueOf(jwtUtil.getRole(oldRefreshToken));

        String newRefresh = rotateRefresh(username, oldRefreshToken, role);
        String newAccess = createAccess(username, role);

        return new ReissueTokens(newAccess, newRefresh);
    }


    //기존 refresh token 삭제 → 새로운 refresh token 생성 및 저장 후 반환

    private String rotateRefresh(String username, String oldRefreshToken, Role role) {

        refreshTokenService.deleteByToken(oldRefreshToken);

        String newRefresh = refreshTokenService.createRefreshToken(username, role);
        refreshTokenService.saveRefreshToken(username, newRefresh);

        return newRefresh;
    }

    //새로운 AccessToken 생성
    private String createAccess(String username, Role role) {
        return jwtUtil.createJwt("access", username, role.name(), 600000L); // 10 minutes
    }
}
