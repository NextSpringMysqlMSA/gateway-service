
# 🔐 Spring Security CORS & JWT 인증 필터 흐름도

본 흐름은 Spring Security 환경에서 CORS 예비 요청 및 JWT 기반 인증을 처리하는 과정을 나타냅니다.  
인증 로직은 JWT 유효성 검사 후 `X-MEMBER-ID`를 헤더에 주입하여 downstream 마이크로서비스에 전달됩니다.

---

## ✅ 처리 절차 요약

| 단계 | 설명 |
|------|------|
| OPTIONS 요청 | CORS 예비 요청일 경우 필터 통과 |
| 인증 제외 경로 | 로그인, 회원가입 등의 인증 제외 URL일 경우 필터 통과 |
| JWT 추출 | `Authorization: Bearer {token}` 헤더에서 토큰 추출 |
| 유효성 검사 | JWT의 서명, 만료 여부 검사 |
| 인증 실패 | 토큰 누락/유효하지 않으면 `401 Unauthorized` 반환 |
| 인증 성공 | 토큰에서 사용자 ID 추출 → `X-MEMBER-ID` 헤더에 삽입 → 다음 필터로 요청 전달

---

## 🔄 인증 필터 흐름도 (Top-Down)

```mermaid
flowchart TD
    %% 노드 정의
    start((Start))
    methodCheck{OPTIONS 메서드인가?}
    bypassCORS[예비 요청 → 필터 통과]
    pathCheck{인증 제외 경로인가?}
    skipAuth[로그인/회원가입 경로 → 필터 통과]
    extractToken["Authorization 헤더에서 JWT 추출"]
    hasToken{토큰 존재 여부}
    reject1[401 Unauthorized 반환]
    validateToken[JWT 유효성 검사]
    isValid{유효한 토큰인가?}
    reject2[401 Unauthorized 반환]
    extractId["토큰에서 회원 ID 추출"]
    addHeader["X-MEMBER-ID 헤더에 회원 ID 주입"]
    forward[다음 필터 또는 서비스로 전달]
    end1((End))
    end2((End))
    end3((End))
    end4((End))
    end5((End))

    %% 플로우
    start --> methodCheck
    methodCheck -- 예 --> bypassCORS --> end1
    methodCheck -- 아니오 --> pathCheck
    pathCheck -- 예 --> skipAuth --> end2
    pathCheck -- 아니오 --> extractToken --> hasToken
    hasToken -- 아니오 --> reject1 --> end3
    hasToken -- 예 --> validateToken --> isValid
    isValid -- 아니오 --> reject2 --> end4
    isValid -- 예 --> extractId --> addHeader --> forward --> end5

    %% 색상 정의 (forest 톤)
    classDef forestGreen fill:#e6f4ea,stroke:#2e7d32,stroke-width:1.5px,color:#2e7d32;
    classDef errorRed fill:#fdecea,stroke:#c62828,color:#c62828;
    classDef terminal fill:#d0f0c0,stroke:#1b5e20,color:#1b5e20;

    %% 적용
    class start,methodCheck,pathCheck,hasToken,isValid,validateToken,extractToken,extractId,addHeader,forward forestGreen;
    class reject1,reject2 errorRed;
    class end1,end2,end3,end4,end5,skipAuth,bypassCORS terminal;
````

---

## 🛠️ 기술 포인트

* **CORS 예비 요청 OPTIONS**: 실제 요청 전 브라우저가 보내는 사전 요청이며, 인증 없이 통과시킴
* **인증 제외 경로**: `/login`, `/signup` 등은 JWT 필터를 건너뜀
* **JWT 검증**: 토큰이 유효한 경우에만 다음 필터로 전달
* **`X-MEMBER-ID` 주입**: 마이크로서비스 간 사용자 식별을 위해 커스텀 헤더 삽입

---

## ✍️ 관련 코드 구조

* `JwtAuthenticationFilter` (`OncePerRequestFilter`)
* `JwtUtils` (토큰 파싱 및 서명 검증)
* 예외 시 `HttpServletResponse.sendError(401 or 403)`

---

## 🔐 보안 확장 방안

* 토큰 재발급 (Refresh Token) 흐름 추가
* 토큰 서명 키를 Vault 또는 AWS Secrets Manager로 외부화
* 요청 로그 및 토큰 추적 시스템 연동

