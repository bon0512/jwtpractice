package com.example.springjwt.service;

import com.example.springjwt.entity.RefreshToken;
import com.example.springjwt.repository.RefreshTokenRepository;
import org.springframework.stereotype.Service;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
    }


    public void saveRefreshToken(Long userId, String token, Long expiry){
        refreshTokenRepository.deleteByUserId(userId);

        RefreshToken refreshToken = RefreshToken.builder()
                .userId(userId)
                .token(token)
                .expiry(expiry)
                .build();

        refreshTokenRepository.save(refreshToken);
    }

    public RefreshToken getByUserId(Long userId){
        return refreshTokenRepository.findByUserId(userId)
                .orElseThrow(() -> new IllegalArgumentException("can't find RefreshToken"));
    }

    public RefreshToken getByToken(String token){
        return refreshTokenRepository.findByToken(token).orElseThrow();
    }

    public void deleteUserToken(Long userId){
        refreshTokenRepository.deleteByUserId(userId);
    }
}
