package com.api.gateway.segurança;

import com.api.gateway.segurança.TokenValidator.ValidationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import java.net.InetSocketAddress;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class JwtAuthenticationFilter implements GlobalFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private final TokenValidator tokenValidator;

    public JwtAuthenticationFilter(TokenValidator tokenValidator) {
        this.tokenValidator = tokenValidator;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();
        String method = request.getMethod().name();

        if ("OPTIONS".equalsIgnoreCase(method)) {
            return chain.filter(exchange);
        }

        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.warn("Requisição sem token: {} {}", method, path);
            return Mono.error(new UnauthorizedException("Token não fornecido"));
        }

        String token = authHeader.substring(7);
        String clientIp = getClientIp(request);

        return tokenValidator.validateToken(token, path, method, clientIp)
                .flatMap(result -> {
                    if (!result.isValid()) {
                        log.warn("Token inválido: {} - {}", result.getError(), path);
                        return Mono.error(new UnauthorizedException(result.getError()));
                    }
                    ServerHttpRequest mutatedRequest = propagateUserInfo(request, result);
                    return chain.filter(exchange.mutate().request(mutatedRequest).build());
                });
    }

    private String getClientIp(ServerHttpRequest request) {
        InetSocketAddress remoteAddress = request.getRemoteAddress();
        if (remoteAddress != null && remoteAddress.getAddress() != null) {
            return remoteAddress.getAddress().getHostAddress();
        }
        return "unknown";
    }

    private ServerHttpRequest propagateUserInfo(ServerHttpRequest request, ValidationResult result) {
        ServerHttpRequest.Builder builder = request.mutate();
        if (result.getUserId() != null) {
            builder.header("X-User-Id", result.getUserId().toString());
        }
        if (result.getUsername() != null) {
            builder.header("X-Username", result.getUsername());
        }
        if (result.getRoles() != null && !result.getRoles().isEmpty()) {
            builder.header("X-User-Roles", String.join(",", result.getRoles()));
        }
        return builder.build();
    }
}