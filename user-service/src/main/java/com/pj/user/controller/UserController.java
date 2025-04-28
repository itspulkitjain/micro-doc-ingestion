package com.pj.user.controller;

import com.pj.user.dto.UserRequest;
import com.pj.user.dto.UserResponse;
import com.pj.user.security.TokenGenerator;
import com.pj.user.security.jwt.JwtUtils;
import com.pj.user.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping(value = "/auth")
public class UserController {

    @Autowired
    UserService service;

    @Autowired
    private AuthenticationManager authenticationManager; // Inject AuthenticationManager

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    TokenGenerator tokenGenerator;

    @PostMapping("/register")
    public ResponseEntity<UserResponse> registerUser(@RequestBody UserRequest request) {
        UserResponse response = new UserResponse();
        try {
            response = service.registerUser(request);
            String token = tokenGenerator.tokenGenerationAndSecurityContextHolderUpdation(request);
            return ResponseEntity.status(HttpStatus.CREATED)
                    .header("Authorization", token)
                    .body(response);
        } catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping(value = "/login")
    public ResponseEntity<UserResponse> loginUser(@RequestBody UserRequest request) {
        UserResponse response = new UserResponse();
        try{
            response = service.authenticateUser(request.getUsername(), request.getPassword());
            String token = tokenGenerator.tokenGenerationAndSecurityContextHolderUpdation(request);
            return ResponseEntity.ok()
                    .header("Authorization", token)
                    .body(response);
        } catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
    }

}
