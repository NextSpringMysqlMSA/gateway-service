package com.nsmm.esg.gatewayservice.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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

/**
 * JWT 인증 필터 클래스
 *
 * <p>Spring WebFlux 환경에서 HTTP 요청에 대한 JWT 토큰 기반 인증을 처리합니다.</p>
 * <p>모든 요청은 이 필터를 통과하며, 인증이 필요한 경로에 대해서는 JWT 토큰 검증을 수행합니다.</p>
 * <p>인증이 성공하면 요청 헤더에 회원 ID를 추가하여 다음 필터 또는 컨트롤러에서 사용할 수 있게 합니다.</p>
 */
@Slf4j  // Lombok의 로깅 기능 활성화
@Component  // 스프링 컴포넌트로 등록
@RequiredArgsConstructor  // Lombok을 사용한 생성자 주입
public class JwtAuthenticationFilter implements WebFilter {

    /**
     * JWT 서명 검증에 사용할 비밀 키
     * application.properties 또는 application.yml에서 jwt.secret 값을 주입받음
     */
    @Value("${jwt.secret}")
    private String secretKey;

    /**
     * WebFilter 인터페이스의 filter 메서드 구현
     * 모든 HTTP 요청에 대해 실행되며 JWT 토큰 검증 및 처리를 수행함
     *
     * @param exchange 현재 HTTP 요청/응답 교환 정보를 담고 있는 객체
     * @param chain 다음 필터로 요청을 전달하기 위한 체인
     * @return 필터 체인 실행 결과에 대한 Mono
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        // 현재 요청의 경로 추출
        String path = exchange.getRequest().getPath().toString();

        // CORS 프리플라이트 요청(OPTIONS 메서드) 처리
        // 브라우저가 실제 요청 전에 보내는 예비 요청으로, 인증 없이 통과시킴
        if (exchange.getRequest().getMethod().name().equalsIgnoreCase("OPTIONS")) {
            return chain.filter(exchange);
        }

        // 인증이 필요 없는 특정 경로 패턴에 대한 처리
        // /auth/ 로 시작하는 경로(로그인, 회원가입 등) 및 /images/ 경로는 인증 없이 통과
        if (path.startsWith("/auth/") || path.startsWith("/images/") || path.startsWith("/actuator/") || path.startsWith("/api/v1/actuator/"))  {
            return chain.filter(exchange);
        }

        // HTTP 요청 헤더에서 JWT 토큰 추출
        String token = resolveToken(exchange);

        // 토큰이 존재하고 유효한 경우 처리
        if (token != null && validateToken(token)) {
            // 토큰에서 회원 ID 추출
            Long memberId = extractMemberId(token);
            log.info("memberId: {}", memberId);

            // 추출한 회원 ID를 요청 헤더에 추가하여 다음 단계에서 사용할 수 있도록 함
            // X-MEMBER-ID 헤더에 회원 ID를 문자열로 변환하여 설정
            ServerWebExchange mutatedExchange = exchange.mutate()
                    .request(builder -> builder.header("X-MEMBER-ID", String.valueOf(memberId)))
                    .build();

            // 변경된 요청으로 다음 필터 체인 실행
            return chain.filter(mutatedExchange);
        } else {
            // 토큰이 없거나 유효하지 않은 경우 401 Unauthorized 응답 반환
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
    }

    /**
     * HTTP 요청 헤더에서 JWT 토큰을 추출하는 메서드
     *
     * <p>Authorization 헤더에서 Bearer 토큰 형식으로 전달된 JWT를 추출합니다.</p>
     * <p>예: "Bearer eyJhbGciOiJIUzI1NiJ9..."</p>
     *
     * @param exchange 현재 HTTP 요청/응답 교환 정보
     * @return 추출된 JWT 토큰 문자열, 토큰이 없거나 형식이 잘못된 경우 null 반환
     */
    private String resolveToken(ServerWebExchange exchange) {
        // HTTP 헤더에서 Authorization 값 추출
        String bearerToken = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        // Bearer 접두사로 시작하는 경우 실제 토큰 부분만 추출하여 반환
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);  // "Bearer " 이후의 실제 토큰 부분만 반환
        }
        return null;  // 토큰이 없거나 형식이 잘못된 경우
    }

    /**
     * JWT 토큰의 유효성을 검증하는 메서드
     *
     * <p>토큰의 서명을 확인하고, 형식이 올바른지 검증합니다.</p>
     * <p>또한 토큰에 subject 클레임이 존재하고 비어있지 않은지 확인합니다.</p>
     *
     * @param token 검증할 JWT 토큰 문자열
     * @return 토큰이 유효하면 true, 그렇지 않으면 false
     */
    private boolean validateToken(String token) {
        try {
            // JWT 서명 검증에 사용할 비밀 키 생성
            SecretKey key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));

            // JWT 파서를 사용하여 토큰 파싱 및 클레임 추출
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(key)  // 서명 검증에 사용할 키 설정
                    .build()
                    .parseClaimsJws(token)  // 토큰 파싱 및 서명 검증
                    .getBody();  // 클레임 본문 가져오기

            // subject 클레임이 존재하고 비어있지 않은지 확인
            return claims.getSubject() != null && !claims.getSubject().isEmpty();
        } catch (Exception e) {
            // 토큰 파싱 과정에서 예외 발생 시 유효하지 않은 토큰으로 판단
            return false;
        }
    }

    /**
     * JWT 토큰에서 회원 ID를 추출하는 메서드
     *
     * <p>토큰의 subject 클레임에서 회원 ID를 추출합니다.</p>
     * <p>이 구현에서는 subject 클레임에 회원 ID가 문자열 형태로 저장되어 있다고 가정합니다.</p>
     *
     * @param token 회원 ID를 추출할 JWT 토큰
     * @return 추출된 회원 ID (Long 타입)
     */
    private Long extractMemberId(String token) {
        // JWT 서명 검증에 사용할 비밀 키 생성
        SecretKey key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));

        // JWT 파서를 사용하여 토큰 파싱 및 클레임 추출
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();

        // subject 클레임에서 회원 ID 추출 및 Long 타입으로 변환
        return Long.parseLong(claims.getSubject());
    }
}