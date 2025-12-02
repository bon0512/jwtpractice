package com.example.springjwt.jwt;

import com.example.springjwt.dto.CustomUserDetails;
import com.example.springjwt.entity.UserEntity;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;

    public JWTFilter(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        //request Authorization ?¤ë”ë¥?ì°¾ìŒ
        String authorization = request.getHeader("Authorization");

        //?¤ë”ê°?ê²€ì¦?
        if(authorization==null || !authorization.startsWith("Bearer ")){
            System.out.println("token null");
            filterChain.doFilter(request,response);

            return ;
        }

        System.out.println("authorization now");

        String token = authorization.split(" ")[1];

        if (jwtUtil.isExpired(token)) {
            System.out.println("token expired");
            filterChain.doFilter(request,response);

            return ;
        }


        //? í°?ì„œ username ê³?role ?ë“
        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);

        UserEntity user = new UserEntity();
        user.setUsername(username);
        user.setRole(role);
        user.setPassword("temppasword");


        //?¤í”„ë§??œíë¦¬í‹° ?¸ì¦ ? í° ?ì„±
        CustomUserDetails customUserDetails = new CustomUserDetails(user);
        Authentication authenticationToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());


        //?¸ì…˜???¬ìš©???±ë¡
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);

        filterChain.doFilter(request,response);

    }
}
