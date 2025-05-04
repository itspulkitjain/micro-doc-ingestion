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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class UserServiceImpl implements UserService{

    private static final Logger log = LoggerFactory.getLogger(UserService.class);

    @Autowired
    UserRepo repo;

    @Autowired
    private RoleRepo roleRepo;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    @Lazy
    private OAuth2AuthorizationService authorizationService;

    @Autowired
    @Lazy
    private OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

    @Autowired
    private AuthorizationServerSettings authorizationServerSettings;

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

    @Override
    public OAuth2AccessToken getOAuth2AccessToken(UserRequest request, Authentication principal) throws ResponseStatusException {
        log.debug("getOAuth2AccessToken method call");
        String clientId = "api-gateway";
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        log.debug("--- Building Token Context ---");
        log.debug("RegisteredClient: {}", (registeredClient != null ? registeredClient.getClientId() : "NULL"));
        log.debug("Principal: {}", (principal != null ? principal.getName() : "NULL"));
        log.debug("Principal Authenticated: {}", (principal != null ? principal.isAuthenticated() : "N/A"));
        log.debug("RegisteredClient Scopes: {}", (registeredClient != null ? registeredClient.getScopes() : "NULL"));
        log.debug("AuthorizationServerSettings: {}", (this.authorizationServerSettings != null ? "Present" : "NULL")); // Check if settings bean is injected
        if (registeredClient == null) {
            log.error("Client registration not found for clientId: {}. Cannot generate token.", clientId);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Client configuration error.");
        }

        if (!registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE) &&
                !registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.PASSWORD)) {
            log.error("Client '{}' is not authorized for user-based grant types.", clientId);
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Client not authorized for this operation.");
        }
        log.debug("tokenContext call");
        OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(principal)
//                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
//                .(this.authorizationServerSettings)
                .authorizedScopes(registeredClient.getScopes())
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .build();

        OAuth2Token generatedToken = tokenGenerator.generate(tokenContext);
        if (generatedToken == null) {
            log.error("Token generator returned null for user: {}", request.getUsername());
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Token generation failed.");
        }
        if (!(generatedToken instanceof OAuth2AccessToken)) {
            log.error("Generated token is not an OAuth2AccessToken for user: {}", request.getUsername());
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to generate access token type.");
        }

        OAuth2AccessToken accessToken = (OAuth2AccessToken) generatedToken;
        log.info("Successfully generated custom access token for user: {}", request.getUsername());
        log.debug("authorization call");

        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(principal.getName())
                .authorizationGrantType(new AuthorizationGrantType("custom_password"))
                .authorizedScopes(registeredClient.getScopes())
                .token(accessToken)
                .build();
        authorizationService.save(authorization);
        log.debug("Saved authorization for custom token flow for user: {}", request.getUsername());
        return accessToken;
    }
}
