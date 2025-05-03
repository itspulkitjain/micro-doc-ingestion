package com.pj.user.service;

import com.pj.user.dto.UserMapper;
import com.pj.user.dto.UserRequest;
import com.pj.user.dto.UserResponse;
import com.pj.user.entity.Role;
import com.pj.user.entity.UserEntity;
import com.pj.user.exception.InvalidCredentialsException;
import com.pj.user.exception.UserAlreadyExistsException;
import com.pj.user.exception.UserNotFoundException;
import com.pj.user.repo.RoleRepo;
import com.pj.user.repo.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class UserServiceImpl implements UserService{

    @Autowired
    UserRepo repo;

    @Autowired
    private RoleRepo roleRepo;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public UserResponse registerUser(UserRequest userRequest) {
        try {
            if (repo.existsByUsernameOrEmail(userRequest.getUsername(), userRequest.getEmail())) {
                throw new UserAlreadyExistsException("Username or Email is already taken.");
            }
            UserEntity user = UserMapper.mapper.toEntity(userRequest);
            user.setPassword(passwordEncoder.encode(userRequest.getPassword()));
            Role userRole = roleRepo.findByName("ROLE_USER")
                    .orElseThrow(() -> new RuntimeException("Role 'ROLE_USER' not found"));
            user.getRoles().add(userRole);
            user = repo.saveAndFlush(user);
            return getUserResponse(user);
        }
        catch (UserAlreadyExistsException e) {
            throw e;
        }
        catch (Exception e){
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred: " + e.getMessage());
        }
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
        throw new InvalidCredentialsException("Unable to authenticate user: "+ username);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<UserEntity> optionalUserEntity = repo.findByUsername(username);
        if (!optionalUserEntity.isPresent()) {
            throw new UserNotFoundException("User not found wi  th username: " + username);
        }
        UserEntity userEntity = optionalUserEntity.get();
        Set<String> roles = userEntity.getRoles().stream()
                .map(Role::getName)
                .collect(Collectors.toSet());
        List<GrantedAuthority> authorities = roles.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
        return new User(userEntity.getUsername(), userEntity.getPassword(), authorities);
    }
}
