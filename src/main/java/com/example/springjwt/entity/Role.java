package com.example.springjwt.entity;

public enum Role {
    ROLE_USER,
    ROLE_ADMIN;

    public String authority() {
        return name();
    }
}
