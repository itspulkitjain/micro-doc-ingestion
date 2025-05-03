package com.pj.user.security;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.pj.user.entity.UserEntity;
import com.pj.user.repo.UserRepo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
public class AuthorizationServerConfig {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationServerConfig.class);

    private final JdbcTemplate jdbcTemplate;
    private final UserRepo userRepo;

    @Value("${rsa.key.private}")
    private String rsaPrivateKeyPem;
    @Value("${rsa.key.public}")
    private String rsaPublicKeyPem;
    @Value("${api.gateway.key}")
    private String apiGatewayKey;

    public AuthorizationServerConfig(PasswordEncoder passwordEncoder, UserRepo userRepo, JdbcTemplate jdbcTemplate) {
        this.userRepo = userRepo;
        this.jdbcTemplate = jdbcTemplate;
    }

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();
        RequestMatcher authorizationServerEndpointsMatcher =
                authorizationServerConfigurer.getEndpointsMatcher();
        authorizationServerConfigurer
                .authorizationEndpoint(authorizationEndpoint ->
                        authorizationEndpoint.consentPage("/oauth2/consent")
                );
        http
                .securityMatcher(authorizationServerEndpointsMatcher)
                .authorizeHttpRequests((authorize) -> authorize
                        .anyRequest().authenticated()
                )
                .csrf((csrf) -> csrf.ignoringRequestMatchers(authorizationServerEndpointsMatcher))
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                )
                .oauth2ResourceServer((resourceServer) -> resourceServer
                        .jwt(Customizer.withDefaults()))
                .with(authorizationServerConfigurer, Customizer.withDefaults());
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers("/login", "/api/users/register").permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder) {
        JdbcRegisteredClientRepository repository = new JdbcRegisteredClientRepository(this.jdbcTemplate);
        String clientId = "api-gateway";
        RegisteredClient existingClient = repository.findByClientId(clientId);
        ClientSettings clientSettings = ClientSettings.builder()
                .requireAuthorizationConsent(true)
                .requireProofKey(false) // *** Temporarily disable PKCE requirement ***
                .build();

        Set<AuthorizationGrantType> grantTypes = Set.of(
                AuthorizationGrantType.AUTHORIZATION_CODE,
                AuthorizationGrantType.REFRESH_TOKEN,
                AuthorizationGrantType.CLIENT_CREDENTIALS,
                AuthorizationGrantType.PASSWORD // *** ADD PASSWORD GRANT TYPE ***
        );

        if (existingClient == null) {
            RegisteredClient apiGatewayClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientSecret(passwordEncoder.encode(apiGatewayKey))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantTypes(types -> types.addAll(grantTypes))
                .redirectUri("http://localhost:8080/login/oauth2/code/" + clientId)
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/" + clientId)
                .scope("read_docs")
                .scope("write_docs")
                .clientSettings(clientSettings)
                .build();
            repository.save(apiGatewayClient);
            System.out.println("Registered new OAuth2 client: " + clientId);
        } else {
            // *** Update existing client to add password grant and update settings ***
            existingClient = RegisteredClient.from(existingClient)
                    .authorizationGrantTypes(types -> {
                        types.clear(); // Clear existing ones first
                        types.addAll(grantTypes); // Add all desired types
                    })
                    .clientSettings(clientSettings) // Apply updated settings
                    .build();
            repository.save(existingClient);
            log.info("Updated existing OAuth2 client '{}' grant types and settings.", clientId);
        }
        return repository;
    }

    /**
     *--- UPDATED to load keys from application properties ---
     *  WARNING: Insecure for production! Use Keystore instead.
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            String publicKeyContent = rsaPublicKeyPem
                    .replaceAll("\\n", "")
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "");
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyContent));
            RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);

            String privateKeyContent = rsaPrivateKeyPem
                    .replaceAll("\\n", "")
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "");
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));
            RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);

            RSAKey rsaKey = new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyID(UUID.randomUUID().toString())
                    .build();

            JWKSet jwkSet = new JWKSet(rsaKey);
            log.info("Successfully loaded RSA keys from application properties for JWKSource.");
            return new ImmutableJWKSet<>(jwkSet);

        } catch (Exception e) {
            log.error("FATAL: Failed to load RSA keys from application properties. Check format and values.", e);
            throw new IllegalStateException("Failed to load RSA keys from properties", e);
        }
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
        return (context) -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                Authentication principal = context.getPrincipal();
                Set<String> authorities = principal.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toSet());
                context.getClaims().claim("authorities", authorities);
                String username = principal.getName();
                context.getClaims().claim("username", username);
                UserEntity userEntity = userRepo.findByUsername(username)
                        .orElse(null);
                if (userEntity != null) {
                    log.debug("Customizing token for user: {}", username);
                    context.getClaims().claim("user_id", userEntity.getId());
                    context.getClaims().claim("email", userEntity.getEmail());
                } else {
                    log.warn("Could not find UserEntity for username '{}' during token customization.", username);
                }
            }
        };
    }
}