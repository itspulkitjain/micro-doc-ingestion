package com.pj.user.service;

import com.pj.user.dto.UserMapper;
import com.pj.user.dto.UserRequest;
import com.pj.user.dto.UserResponse;
import com.pj.user.entity.UserEntity;
import com.pj.user.repo.UserRepo;
import org.apache.http.auth.AuthenticationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class UserServiceImpl implements UserService{

    @Autowired
    UserRepo repo;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public UserResponse registerUser(UserRequest userRequest) {
        UserEntity user = UserMapper.mapper.toEntity(userRequest);
        user.setPassword(passwordEncoder.encode(userRequest.getPassword()));
        user = repo.saveAndFlush(user);
        return getUserResponse(user);
    }

    private UserResponse getUserResponse(UserEntity user) {
        UserResponse response = new UserResponse();
        response.setUser(UserMapper.mapper.toJson(user));
        return response;
    }

    @Override
    public UserResponse authenticateUser(String username, String password) {
        Optional<UserEntity> user = repo.findByUsername(username);
        if (user.isPresent() && passwordEncoder.matches(password, user.get().getPassword())) {
            return getUserResponse(user.get());
        }
        throw new UsernameNotFoundException("Unable to authenticate user: "+ username);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<UserEntity> user = repo.findByUsername(username);
        if (!user.isPresent()) {
            throw new UsernameNotFoundException("User not found with username: " + username);
        }
        UserEntity u = user.get();
        List<GrantedAuthority> authorities = new ArrayList<>(List.of(new SimpleGrantedAuthority("ROLE_USER")));
        return new User(u.getUsername(), u.getPassword(), authorities);
    }
}
