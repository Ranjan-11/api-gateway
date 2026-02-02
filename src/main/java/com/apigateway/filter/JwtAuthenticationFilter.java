package com.apigateway.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

@Component
public class JwtAuthenticationFilter implements GlobalFilter , Ordered {
    private static final String SECRET_KEY = "secret12345";
    private static final List<String> openEndPoints = List.of(
            "/auth/api/roleBased/auth/SignUp",
            "/auth/api/roleBased/auth/login"
    );
    private static final Map<String , List<String>> protectedEndPointsWithRoles = Map.of(
            "/micro1/message",List.of("ROLE_ADMIN")
    );
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String requestPath = exchange.getRequest().getURI().getPath();
        if (isPublicEndPoint(requestPath)){
            return chain.filter(exchange);
        }
        String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
        
        if (authHeader == null || !authHeader.startsWith("Bearer ")){
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String token = authHeader.substring(7);
        try {
            DecodedJWT jwtVerify = JWT.require(Algorithm.HMAC256(SECRET_KEY))
                    .build()
                    .verify(token);
            String role = jwtVerify.getClaim("role").asString();

            System.out.println("Request Path" + requestPath);
            System.out.println("Role from token " + role);

            if (!isAuthorized(requestPath,role)){
                exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                return exchange.getResponse().setComplete();
            }
            exchange = exchange.mutate()
                    .request(r->r.header("X-User-Role",role))
                    .build();
        }catch (JWTVerificationException e){
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
        return chain.filter(exchange);
    }



    private boolean isPublicEndPoint(String path) {
        return openEndPoints.stream()
            .anyMatch(path::equalsIgnoreCase);
    }

    private boolean isAuthorized(String requestPath, String role) {
        for(Map.Entry<String , List<String>> entry : protectedEndPointsWithRoles.entrySet()){
            String protectedPath = entry.getKey();
            List<String> allowedRoles = entry.getValue();

            if (protectedPath.startsWith(protectedPath)){
                System.out.println("Matched ProtectedPath" + protectedPath + "| Allowed roles :" + allowedRoles);
                return allowedRoles.contains(role);
            }
        }
        return true;
    }
    @Override
    public int getOrder() {
        return -1;
    }
}
