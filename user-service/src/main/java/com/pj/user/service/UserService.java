package com.pj.user.service;

import com.pj.user.dto.UserRequest;
import com.pj.user.dto.UserResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.web.server.ResponseStatusException;

public interface UserService extends UserDetailsService {
    UserResponse registerUser(UserRequest userRequest);

    UserResponse authenticateUser(String username, String password);

    OAuth2AccessToken getOAuth2AccessToken(UserRequest request, Authentication principal) throws ResponseStatusException;
}
