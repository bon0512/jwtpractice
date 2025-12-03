package com.example.springjwt.service;

import com.example.springjwt.entity.RefreshTokenEntity;
import com.example.springjwt.repository.RefreshTokenRepository;
import org.springframework.stereotype.Service;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
    }


    public void saveRefreshToken(String username, String token, Long expiry){

        // 기존 유저의 refresh 삭제 (Rotation)
        refreshTokenRepository.deleteByUsername(username);

        RefreshTokenEntity refreshToken = RefreshTokenEntity.builder()
                .username(username)
                .token(token)
                .expiry(expiry)
                .build();

        refreshTokenRepository.save(refreshToken);
    }

    public RefreshTokenEntity getByUsername(String username){
        return refreshTokenRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("can't find RefreshToken"));
    }

    public RefreshTokenEntity getByToken(String token){
        return refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> new IllegalArgumentException("can't find RefreshToken"));
    }

    public void deleteUserToken(String username){
        refreshTokenRepository.deleteByUsername(username);
    }
}
