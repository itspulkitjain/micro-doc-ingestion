package com.pj.user.service;

import com.pj.user.dto.UserRequest;
import com.pj.user.dto.UserResponse;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface UserService extends UserDetailsService {
    UserResponse registerUser(UserRequest userRequest);

    UserResponse authenticateUser(String username, String password);
}
