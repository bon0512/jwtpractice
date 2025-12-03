package com.example.springjwt.repository;

import com.example.springjwt.entity.RefreshTokenEntity;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshTokenEntity,Long> {

    Boolean existsByToken(String token);

    Optional<RefreshTokenEntity> findByUsername(String username);

    Optional<RefreshTokenEntity> findByToken(String token);

    @Transactional
    void deleteByUsername(String username);

    @Transactional
    void deleteByToken(String token);
}

