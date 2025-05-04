package com.pj.api.gateway.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;

import java.util.List;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    private static final String USER_HEADER = "X-Authenticated-User";
    private static final String AUTHORITIES_HEADER = "X-User-Authorities";
    private static final String USER_ID_HEADER = "X-User-ID";
    private static final String USER_EMAIL_HEADER = "X-User-Email";

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http, WebFilter authenticationHeaderFilter) {
        http
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/oauth2/**", "/login", "/logout", "/api/users/register", "/api/users/auth/token").permitAll()
                        .pathMatchers("/api/docs/**").authenticated()
                        .anyExchange().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(Customizer.withDefaults())
                )
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .addFilterAfter(authenticationHeaderFilter, SecurityWebFiltersOrder.AUTHENTICATION);
        return http.build();
    }

    @Bean
    public WebFilter authenticationHeaderFilter() {
        return (exchange, chain) -> {
            return exchange.getPrincipal()
                    .filter(principal -> principal instanceof JwtAuthenticationToken)
                    .cast(JwtAuthenticationToken.class)
                    .flatMap(jwtAuth -> {

                        Jwt jwt = jwtAuth.getToken();
                        String username = jwt.getSubject();
                        List<String> authoritiesList = jwt.getClaimAsStringList("authorities");
                        String authoritiesString = authoritiesList != null ? String.join(",", authoritiesList) : "";
                        String userId = jwt.getClaimAsString("user_id");
                        String email = jwt.getClaimAsString("email");

                        if (username != null) {
                            log.debug("Propagating headers - User: {}, ID: {}, Email: {}, Authorities: [{}]", username, userId, email, authoritiesString);
                            ServerHttpRequest.Builder requestBuilder = exchange.getRequest().mutate();
                            requestBuilder.header(USER_HEADER, username);
                            requestBuilder.header(AUTHORITIES_HEADER, authoritiesString);
                            if (userId != null) {
                                requestBuilder.header(USER_ID_HEADER, String.valueOf(userId));
                            }
                            if (email != null) {
                                requestBuilder.header(USER_EMAIL_HEADER, email);
                            }
                            ServerHttpRequest mutatedRequest = requestBuilder.build();
                            ServerWebExchange mutatedExchange = exchange.mutate().request(mutatedRequest).build();
                            return chain.filter(mutatedExchange);
                        } else {
                            log.warn("JWT subject (username) is null after successful validation. Cannot propagate user header.");
                            return chain.filter(exchange); // Continue without headers
                        }
                    })
                    .switchIfEmpty(chain.filter(exchange));
        };
    }
}
