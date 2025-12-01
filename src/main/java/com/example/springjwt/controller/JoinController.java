package com.example.springjwt.controller;


import com.example.springjwt.dto.JoinDTO;
import com.example.springjwt.service.JoinService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JoinController {


    private final JoinService joinService;

    public JoinController(JoinService joinService) {
        this.joinService = joinService;
    }

    @PostMapping("/join")
    public String joinProcess(JoinDTO joinDto){
        joinService.joinProcess(joinDto);
        return "ok";
    }
}
