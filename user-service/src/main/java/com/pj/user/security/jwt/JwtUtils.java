package com.pj.user.security.jwt;

import com.pj.user.exception.JwtTokenMalformedException;
import com.pj.user.exception.JwtTokenMissingException;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.stream.Collectors;

@Component
public class JwtUtils {

	@Value("${foneapp.app.jwt.secret}")
	private String jwtSecret;

	@Value("${foneapp.app.jwt.expiration.duration}")
	private Duration jwtExpirationDuration;
	
	public String generateJwtToken(Authentication authentication) {
		User userPrincipal = (User) authentication.getPrincipal();
		Date now = new Date();
		List<String> roles = userPrincipal.getAuthorities().stream()
				.map(GrantedAuthority::getAuthority)
				.collect(Collectors.toList());
		String id = userPrincipal.getUsername(); // changed

		return Jwts.builder()
				.setId(id)  // added
				.setSubject(userPrincipal.getUsername())
				.claim("roles", roles)
				.setIssuedAt(now)
				.setExpiration(new Date(now.getTime() + jwtExpirationDuration.toMillis()))
				.signWith(getSigningKey(), SignatureAlgorithm.HS256)
				.compact();
	}


	private SecretKey getSigningKey() {
		byte[] keyBytes = null;
		keyBytes = this.jwtSecret.getBytes(StandardCharsets.UTF_8);
		return Keys.hmacShaKeyFor(keyBytes);
	}
	
	public String getUserNameFromJwtToken(String token) {
		return Jwts.parser().setSigningKey(getSigningKey()).build().parseClaimsJws(token).getBody().getSubject();
	}

	public Set<String> getRolesFromJwtToken(String token) {
		return Jwts.parser().setSigningKey(getSigningKey()).build().parseClaimsJws(token).getBody().get("roles", Set.class);
	}

	public Map<String, String> validateExpiryAndGetClaimsFromJwtToken(String token) {
		Map<String, String> claims = new HashMap<>();
		try {
			Claims jwtClaims = Jwts.parser().
				setSigningKey(getSigningKey()).
				build().parseClaimsJws(token).getBody();
			claims.put("username", jwtClaims.getSubject());
			return claims;
		} catch (ExpiredJwtException e) {
			claims.put("username", e.getClaims().getSubject());
			return claims;
		}				
	}
	
	public boolean validateJwtToken(String authToken) {
		try {
			Jwts.parser().
			setSigningKey(getSigningKey()).
			build().parseClaimsJws(authToken);
			return true;
		} catch (MalformedJwtException e) {
			throw new JwtTokenMalformedException("Invalid JWT token");
		} catch (ExpiredJwtException e) {
			throw new JwtTokenMalformedException("Expired JWT token");
		} catch (UnsupportedJwtException e) {
			 throw new JwtTokenMalformedException("Unsupported JWT token");
		} catch (IllegalArgumentException e) {
			throw new JwtTokenMissingException("JWT claims string is empty.");
		}
		
	}
}