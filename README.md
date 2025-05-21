## 🌲 Spring Security CORS & JWT 인증 필터 흐름도 (Left to Right)

```mermaid
flowchart LR
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
