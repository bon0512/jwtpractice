package com.example.springjwt.service;


import com.example.springjwt.dto.UserRequestDTO;
import com.example.springjwt.entity.UserEntity;
import com.example.springjwt.repository.UserRepository;
import jakarta.transaction.Transactional;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.nio.file.AccessDeniedException;

@Service
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public UserService(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    // username 중복 검사
    @Transactional
    public Boolean existUser(UserRequestDTO dto){
        return userRepository.existsByUsername(dto.getUsername());
    }

    // 유저 정보 수정 (로컬 계정만 가능)
    @Transactional
    public Long updateUser(UserRequestDTO dto) throws AccessDeniedException {

        // 본인 계정인지 확인
        String sessionUsername = SecurityContextHolder.getContext().getAuthentication().getName();
        if (!sessionUsername.equals(dto.getUsername())) {
            throw new AccessDeniedException("Access denied: session user does not match target user");
        }

        // 유저 조회
        UserEntity entity = userRepository.findByUsername(dto.getUsername());
        if (entity == null) {
            throw new UsernameNotFoundException(dto.getUsername());
        }

        if (!"local".equals(entity.getProvider())) {
            throw new IllegalArgumentException("Only local accounts can be updated");
        }

        // 업데이트 적용
        //  이름 수정
        if (dto.getUsername() != null && !dto.getUsername().isBlank()) {
            entity.setName(dto.getUsername());
        }

        // 비밀번호 수정(암호화 필수)
        if (dto.getPassword() != null && !dto.getPassword().isBlank()) {
            entity.setPassword(bCryptPasswordEncoder.encode(dto.getPassword()));
        }

        return userRepository.save(entity).getId();
    }

    @Transactional
    @Override
    // 로그인 시 인증을 위한 유저 정보 로드
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity user = userRepository.findByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException("User not found: " + username);
        }

        return User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .roles(user.getRole().name())
                .build();
    }
}
