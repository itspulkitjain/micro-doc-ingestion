package com.pj.docis.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;


@Component
public class HeaderAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(HeaderAuthenticationFilter.class);

    private static final String USER_HEADER = "X-Authenticated-User";
    private static final String AUTHORITIES_HEADER = "X-User-Authorities";
    private static final String USER_ID_HEADER = "X-User-ID";
    private static final String USER_EMAIL_HEADER = "X-User-Email";

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        String username = request.getHeader(USER_HEADER);
        String authoritiesHeader = request.getHeader(AUTHORITIES_HEADER);
        String userId = request.getHeader(USER_ID_HEADER);
        String email = request.getHeader(USER_EMAIL_HEADER);

        if (StringUtils.hasText(username)) {
            List<SimpleGrantedAuthority> authorities;
            if (StringUtils.hasText(authoritiesHeader)) {
                authorities = Arrays.stream(authoritiesHeader.split(","))
                        .filter(StringUtils::hasText)
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());
                log.debug("User '{}' - Authorities from header: {}", username, authorities);
            } else {
                authorities = Collections.emptyList();
                log.warn("User '{}' header present, but no authorities header '{}' found.", username, AUTHORITIES_HEADER);
            }

            Map<String, String> principalDetails = new HashMap<>();
            principalDetails.put("username", username);
            if (StringUtils.hasText(userId)) {
                principalDetails.put("userId", userId);
            }
            if (StringUtils.hasText(email)) {
                principalDetails.put("email", email);
            }

            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    principalDetails,
                    null,
                    authorities);

            SecurityContextHolder.getContext().setAuthentication(authentication);
            log.debug("SecurityContext populated for user: {}, details: {}", username, principalDetails);

        } else {
            log.trace("No '{}' header found. Clearing SecurityContext.", USER_HEADER);
            SecurityContextHolder.clearContext();
        }
        filterChain.doFilter(request, response);
    }
}

