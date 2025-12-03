package com.example.springjwt.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class ReissueTokens {
    private String access;
    private String refresh;
}
