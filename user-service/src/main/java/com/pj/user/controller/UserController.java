package com.pj.user.controller;

import com.pj.user.dto.UserRequest;
import com.pj.user.dto.UserResponse;
import com.pj.user.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(value = "/api/users")
public class UserController {

    @Autowired
    UserService service;

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

}
