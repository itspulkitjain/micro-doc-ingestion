package com.pj.user.controller;

import com.pj.user.dto.UserRequest;
import com.pj.user.dto.UserResponse;
import com.pj.user.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.web.ErrorResponse;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(value = "/api/users")
public class UserController {

    private static final Logger log = LoggerFactory.getLogger(UserController.class);

    @Autowired
    private UserService service;

    @Autowired
    private AuthenticationManager authenticationManager;

    @PostMapping("/register")
    public ResponseEntity<UserResponse> registerUser(@RequestBody UserRequest request) {
        UserResponse response = new UserResponse();
        response = service.registerUser(request);
        response.setSuccess(true);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

//    @PostMapping(value = "/login")
//    public ResponseEntity<UserResponse> loginUser(@RequestBody UserRequest request) {
//        UserResponse response = new UserResponse();
//        response = service.authenticateUser(request.getUsername(), request.getPassword());
//        String token = tokenGenerator.tokenGenerationAndSecurityContextHolderUpdation(request);
//        return ResponseEntity.ok()
//                .header("Authorization", token)
//                .body(response);
//    }

    @PostMapping("/auth/token")
    public ResponseEntity<?> getAccessToken(@RequestBody UserRequest request) {
        log.info("Attempting custom token generation for user: {}", request.getUsername());
        UserResponse response = new UserResponse();
        Authentication principal = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );

        OAuth2AccessToken accessToken = service.getOAuth2AccessToken(request, principal);
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken.getTokenValue());
        return ResponseEntity.ok().headers(headers).build();
    }

}
