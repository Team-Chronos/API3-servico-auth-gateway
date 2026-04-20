package com.api.gateway.segurança;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Date;
import java.util.List;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secret;
    private SecretKey secretKey;

    private SecretKey getSecretKey() {
        if (secretKey == null) {
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-384");
                byte[] hash = digest.digest(secret.getBytes(StandardCharsets.UTF_8));
                secretKey = Keys.hmacShaKeyFor(hash);
            } catch (Exception e) {
                byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
                byte[] validKeyBytes = new byte[48];
                for (int i = 0; i < 48; i++) {
                    validKeyBytes[i] = keyBytes[i % keyBytes.length];
                }
                secretKey = Keys.hmacShaKeyFor(validKeyBytes);
            }
        }
        return secretKey;
    }

    public Claims extractClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSecretKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean isTokenValid(String token) {
        try {
            Claims claims = extractClaims(token);
            return !claims.getExpiration().before(new Date());
        } catch (Exception e) {
            return false;
        }
    }

    public String getUsernameFromToken(String token) {
        try {
            return extractClaims(token).getSubject();
        } catch (Exception e) {
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    public List<String> getRolesFromToken(String token) {
        try {
            return extractClaims(token).get("roles", List.class);
        } catch (Exception e) {
            return List.of();
        }
    }

    public Long getUserIdFromToken(String token) {
        try {
            Object userId = extractClaims(token).get("userId");
            if (userId instanceof Number) return ((Number) userId).longValue();
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    public boolean hasRole(String token, String role) {
        return getRolesFromToken(token).contains(role);
    }

    public boolean hasAnyRole(String token, String... roles) {
        List<String> userRoles = getRolesFromToken(token);
        for (String role : roles) {
            if (userRoles.contains(role)) return true;
        }
        return false;
    }

    public Date getExpirationDate(String token) {
        try {
            return extractClaims(token).getExpiration();
        } catch (Exception e) {
            return null;
        }
    }
}