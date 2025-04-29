package com.nsmm.esg.gatewayservice.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements WebFilter {

    @Value("${jwt.secret}")
    private String secretKey;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        // 1. 요청 경로(path) 추출
        String path = exchange.getRequest().getPath().toString();

        // 2. 인증 제외 경로 처리 (ex: /auth/** 는 회원가입, 로그인 같은 공개 API이므로 인증 검증 생략)
        if (path.startsWith("/auth/")) {
            return chain.filter(exchange); // 필터 타지 않고 바로 다음 필터로 넘김
        }

        // 3. Authorization 헤더에서 JWT 토큰 추출
        String token = resolveToken(exchange);

        // 4. 토큰이 존재하고, 유효한 경우 요청을 계속 진행
        if (token != null && validateToken(token)) {
            return chain.filter(exchange); // JWT 검증 통과 → 요청 정상 진행
        } else {
            // 5. 토큰이 없거나, 검증 실패한 경우 401 Unauthorized 반환
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete(); // 요청 종료
        }
    }

    /**
     * Authorization 헤더에서 Bearer 토큰 추출하는 메서드
     * @param exchange HTTP 요청 정보
     * @return Bearer 토큰 문자열 (Bearer 제외) 또는 null
     */
    private String resolveToken(ServerWebExchange exchange) {
        String bearerToken = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        // Authorization 헤더가 존재하고 "Bearer "로 시작하는 경우만 토큰 추출
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7); // "Bearer " 부분 잘라내고 토큰만 반환
        }
        return null; // 토큰 없으면 null 반환
    }

    /**
     * JWT 토큰의 유효성을 검증하는 메서드
     * - 서명(Signature) 검증
     * - 토큰이 변조되지 않았는지, 만료되지 않았는지 확인
     * @param token 클라이언트로부터 전달받은 JWT 토큰
     * @return 유효하면 true, 그렇지 않으면 false
     */
    private boolean validateToken(String token) {
        try {
            // 1. JWT 서명을 검증하기 위한 SecretKey 생성
            SecretKey key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));

            // 2. JWT를 파싱하여 Claims(페이로드) 가져오기
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(key) // 서명 키 설정
                    .build()
                    .parseClaimsJws(token) // 토큰 파싱
                    .getBody();

            // 3. Subject(일반적으로 사용자 ID나 이메일)가 존재하는지 확인
            return !claims.getSubject().isEmpty();
        } catch (Exception e) {
            // 4. 파싱 에러 (서명 불일치, 만료, 잘못된 토큰 등) 발생 시 false 반환
            return false;
        }
    }

}
