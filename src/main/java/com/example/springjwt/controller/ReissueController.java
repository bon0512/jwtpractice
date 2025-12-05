package com.example.springjwt.controller;


import com.example.springjwt.dto.ReissueTokens;
import com.example.springjwt.jwt.JWTUtil;
import com.example.springjwt.service.ReissueService;
import com.example.springjwt.service.RefreshTokenService;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ReissueController {

    private final ReissueService reissueService;
    private final RefreshTokenService refreshTokenService;

    public ReissueController(ReissueService reissueService, RefreshTokenService refreshTokenService) {
        this.reissueService = reissueService;
        this.refreshTokenService = refreshTokenService;
    }

    @PostMapping("/reissue")
    public ResponseEntity<?> reissue(HttpServletRequest request, HttpServletResponse response) {

        try {
            // refresh 토큰 꺼내기
            Cookie[] cookies = request.getCookies();
            String refreshToken = reissueService.extractRefreshToken(cookies);

            // 새 access, refresh발급
            ReissueTokens reissueTokens = reissueService.reissueTokens(refreshToken);

            // 응답 헤더에 access 넣기
            response.setHeader("access", reissueTokens.getAccess());
            response.addCookie(refreshTokenService.createRefreshCookie(reissueTokens.getRefresh()));


            return new ResponseEntity<>(HttpStatus.OK);

        } catch (IllegalArgumentException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }


}
