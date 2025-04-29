package com.pj.user.security;

import com.pj.user.dto.UserRequest;
import com.pj.user.security.jwt.JwtUtils;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
public class TokenGenerator {

    @Autowired
    private AuthenticationManager authenticationManager; // Inject AuthenticationManager

    @Autowired
    private JwtUtils jwtUtils;

    @Transactional
    public String tokenGenerationAndSecurityContextHolderUpdation(UserRequest userRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(userRequest.getUsername(), userRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        return jwtUtils.generateJwtToken(authentication);
    }
}
