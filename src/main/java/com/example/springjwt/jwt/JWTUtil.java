package com.example.springjwt.jwt;


import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JWTUtil {

    private SecretKey secretKey;

    public JWTUtil(@Value("${spring.jwt.secret}") String secret) {

        secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    /**
     * parser()로 JWT 해석 준비
     * verifyWith(secretKey) → 이 키로 서명 검증함
     * parseSignedClaims(token) → 실제 JWT를 파싱
     * getPayload() → JWT 바디 부분
     * "username" claim 값을 String으로 가져옴
     */

    public String getUsername(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username", String.class);
    }

    /**
     * username 과 동일한 구조로 role 역할 추출
     *
     */
    public String getRole(String token) {

        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
    }

    /**
     * 토큰 안의 exp(만료 시간) 가져와서
     * 현재 시간보다 이전인지 비교
     * true면 → 만료됨(expired)
     */
    public Boolean isExpired(String token) {

        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
    }


    public String getCategory(String token){
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("category", String.class);

    }

    /**
     * claim 추가 → username, role
     * issuedAt(발급 시간)
     * expiration(만료 시간)
     * signWith(secretKey) → 비밀키로 HS256 서명
     * compact() → 최종 JWT 문자열 생성
     */

    public String createJwt(String category, String username, String role, Long expiredMs) {

        return Jwts.builder()
                .claim("category",category)
                .claim("username", username)
                .claim("role", role)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiredMs))
                .signWith(secretKey)
                .compact();
    }
}
