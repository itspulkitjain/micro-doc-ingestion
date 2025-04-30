package com.pj.api.gateway.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
                .authorizeExchange(exchange -> exchange
                        .matchers(new AntPathRequestMatcher("/login")).permitAll()
                        .pathMatchers("/api/**").authenticated()
                        .anyExchange().permitAll()
                );
                http.oauth2ResourceServer(server -> server
                        .jwt(jwt -> jwt.decoder(jwtDecoder()))
                )
                .build();
        http
                .authorizeExchange()
                .pathMatchers("/login").permitAll()
                .pathMatchers("/api/**").authenticated()
                .anyExchange().permitAll()
                .and()
                .oauth2ResourceServer()
                .jwt();
        return http.build();
    }

    @Bean
    JwtDecoder jwtDecoder() {
        String jwkSetUri = "http://user-service:9092/oauth2/jwks";
        return NimbusReactiveJwtDecoder.withJwkSetUri(jwkSetUri).build();
    }
}