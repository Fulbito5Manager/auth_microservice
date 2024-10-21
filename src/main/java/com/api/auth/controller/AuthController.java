package com.api.auth.controller;

import com.api.auth.controller.dto.AuthCreateUserRequest;
import com.api.auth.controller.dto.AuthLoginRequest;
import com.api.auth.controller.dto.AuthResponse;
import com.api.auth.service.UserDetailsServiceImpl;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    private UserDetailsServiceImpl userDetailsService;
    @PostMapping("/sign-up")
    public ResponseEntity<AuthResponse> register(@RequestBody @Valid AuthCreateUserRequest authCreateUser){
        return new ResponseEntity<>(this.userDetailsService.createUser(authCreateUser), HttpStatus.CREATED);
    }

    @PostMapping("/log-in")
    public ResponseEntity<AuthResponse> login(@RequestBody @Valid AuthLoginRequest userRequest){
        return  new ResponseEntity<>(this.userDetailsService.loginUser(userRequest), HttpStatus.OK);
    }

    @GetMapping("/get")
    @PreAuthorize("hasAuthority('READ')")
    public String getAuth(){
        return "Hello World!";
    }
}
