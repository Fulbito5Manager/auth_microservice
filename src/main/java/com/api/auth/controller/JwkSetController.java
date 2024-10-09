package com.api.auth.controller;

import com.api.auth.util.JwtUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class JwkSetController {

    private final JwtUtils jwtUtils;

    public JwkSetController(JwtUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }

    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> getJwkSet() throws Exception {
        // Delegar la obtención del JWK Set a JwtUtils
        return jwtUtils.getJwkSet();
    }
}