package com.example.springjwt.repository;

import com.example.springjwt.entity.UserEntity;
import org.apache.catalina.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<UserEntity,Long> {

    Boolean existsByUsername(String username);
    UserEntity findByUsername(String username);
    Optional<UserEntity> findByUsernameAndProvider(String username, String provider);
}
