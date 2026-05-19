package com.api.gateway.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class AuditoriaGatewayFilter implements GlobalFilter {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        try {
            String tokenBearer = exchange.getRequest().getHeaders().getFirst("Authorization");

            if (tokenBearer != null && tokenBearer.startsWith("Bearer ")) {
                String tokenPuro = tokenBearer.substring(7);
                DecodedJWT jwt = JWT.decode(tokenPuro);

                String idUsuarioStr = null;

                if (!jwt.getClaim("id").isNull()) {
                    idUsuarioStr = jwt.getClaim("id").asString();

                    // Se não veio como String, tenta extrair como Integer/Long e converte
                    if (idUsuarioStr == null) {
                        Long idLong = jwt.getClaim("id").asLong();
                        if (idLong != null) {
                            idUsuarioStr = String.valueOf(idLong);
                        }
                    }
                }
                if (idUsuarioStr != null && !idUsuarioStr.trim().isEmpty()) {
                    ServerHttpRequest requestModificada = exchange.getRequest().mutate()
                            .header("x-user-id", idUsuarioStr) // Injeta em minúsculo
                            .build();
                    return chain.filter(exchange.mutate().request(requestModificada).build());
                } else {
                    System.out
                            .println("Auditoria Gateway: Chave 'id' não encontrada ou nula dentro do Payload do JWT.");
                }
            }
        } catch (Exception e) {
            System.out.println("Auditoria Gateway [Erro Capturado]: " + e.getMessage());
            e.printStackTrace();
        }
        // Se o token falhar ou for nulo, deixa o fluxo seguir de forma limpa
        return chain.filter(exchange);
    }
}