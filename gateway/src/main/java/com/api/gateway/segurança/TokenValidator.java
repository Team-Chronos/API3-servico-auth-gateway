package com.api.gateway.segurança;

import com.api.gateway.segurança.AuthorizationProperties.Rule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import reactor.core.publisher.Mono;
import java.time.Duration;
import java.util.Date;
import java.util.List;

@Component
public class TokenValidator {

    private static final Logger log = LoggerFactory.getLogger(TokenValidator.class);

    private final JwtUtil jwtUtil;
    private final ReactiveRedisTemplate<String, String> redisTemplate;
    private final AuthorizationProperties authProperties;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    public TokenValidator(JwtUtil jwtUtil, ReactiveRedisTemplate<String, String> redisTemplate,
                          AuthorizationProperties authProperties) {
        this.jwtUtil = jwtUtil;
        this.redisTemplate = redisTemplate;
        this.authProperties = authProperties;
    }

    public Mono<ValidationResult> validateToken(String token, String path, String method, String clientIp) {
        return isTokenBlacklisted(token)
                .flatMap(blacklisted -> {
                    if (blacklisted) {
                        log.warn("Token revogado: {}", maskToken(token));
                        return Mono.just(ValidationResult.invalid("Token revogado"));
                    }
                    if (!jwtUtil.isTokenValid(token)) {
                        log.warn("Token inválido ou expirado: {}", maskToken(token));
                        return Mono.just(ValidationResult.invalid("Token inválido ou expirado"));
                    }
                    return checkRateLimit("token:" + token, authProperties.getRateLimits().getPerToken())
                            .flatMap(rateOk -> {
                                if (!rateOk) {
                                    return Mono.just(ValidationResult.invalid("Rate limit excedido para este token"));
                                }
                                return checkRateLimit("ip:" + clientIp, authProperties.getRateLimits().getPerIp())
                                        .flatMap(ipOk -> {
                                            if (!ipOk) {
                                                return Mono.just(ValidationResult.invalid("Rate limit excedido para este IP"));
                                            }
                                            return checkPermissions(token, path, method);
                                        });
                            });
                });
    }

    public Mono<Boolean> checkRateLimit(String key, int limit) {
        String rateKey = "rate:" + key;
        return redisTemplate.opsForValue().increment(rateKey)
                .flatMap(current -> {
                    if (current == 1) {
                        return redisTemplate.expire(rateKey, Duration.ofSeconds(60))
                                .thenReturn(current <= limit);
                    }
                    return Mono.just(current <= limit);
                })
                .defaultIfEmpty(false);
    }

    private Mono<Boolean> isTokenBlacklisted(String token) {
        String key = "blacklist:" + token;
        return redisTemplate.hasKey(key);
    }

    private Mono<ValidationResult> checkPermissions(String token, String path, String method) {
        if (isPublicPath(path)) {
            return Mono.just(ValidationResult.success(token, jwtUtil));
        }

        for (Rule rule : authProperties.getRules()) {
            if (pathMatcher.match(rule.getPath(), path)) {
                if (rule.getMethods().isEmpty() || rule.getMethods().contains("*") || rule.getMethods().contains(method)) {
                    if (rule.getRoles().isEmpty()) {
                        return Mono.just(ValidationResult.success(token, jwtUtil));
                    }
                    if (jwtUtil.hasAnyRole(token, rule.getRoles().toArray(new String[0]))) {
                        return Mono.just(ValidationResult.success(token, jwtUtil));
                    } else {
                        log.warn("Acesso negado: usuário {} não possui as roles {} para {} {}",
                                jwtUtil.getUsernameFromToken(token), rule.getRoles(), method, path);
                        return Mono.just(ValidationResult.invalid("Permissão negada"));
                    }
                }
            }
        }
        return Mono.just(ValidationResult.success(token, jwtUtil));
    }

    private boolean isPublicPath(String path) {
        return authProperties.getPublicPaths().stream().anyMatch(path::startsWith);
    }

    public Mono<Void> revokeToken(String token) {
        if (!jwtUtil.isTokenValid(token)) return Mono.empty();
        Date exp = jwtUtil.getExpirationDate(token);
        long ttl = exp != null ? exp.getTime() - System.currentTimeMillis() : 3600000;
        if (ttl > 0) {
            String key = "blacklist:" + token;
            return redisTemplate.opsForValue().set(key, "", Duration.ofMillis(ttl)).then();
        }
        return Mono.empty();
    }

    private static String maskToken(String token) {
        if (token == null || token.length() < 8) return "***";
        return token.substring(0, 4) + "..." + token.substring(token.length() - 4);
    }

    public static class ValidationResult {
        private final boolean valid;
        private final String error;
        private final String username;
        private final Long userId;
        private final List<String> roles;

        private ValidationResult(boolean valid, String error, String username, Long userId, List<String> roles) {
            this.valid = valid;
            this.error = error;
            this.username = username;
            this.userId = userId;
            this.roles = roles;
        }

        public static ValidationResult success(String token, JwtUtil jwtUtil) {
            return new ValidationResult(true, null,
                    jwtUtil.getUsernameFromToken(token),
                    jwtUtil.getUserIdFromToken(token),
                    jwtUtil.getRolesFromToken(token));
        }

        public static ValidationResult invalid(String error) {
            return new ValidationResult(false, error, null, null, List.of());
        }

        public boolean isValid() { return valid; }
        public String getError() { return error; }
        public String getUsername() { return username; }
        public Long getUserId() { return userId; }
        public List<String> getRoles() { return roles; }
    }
}