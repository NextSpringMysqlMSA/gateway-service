# 빌드 스테이지
FROM eclipse-temurin:17-jdk-alpine AS build
WORKDIR /workspace/app

# Gradle 파일 복사
COPY gradlew .
COPY gradle gradle
COPY build.gradle .
COPY settings.gradle .
COPY src src

# 실행 권한 부여 및 빌드
RUN chmod +x ./gradlew
RUN ./gradlew clean build -x test

# 실행 스테이지
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app

# 타임존 설정
RUN apk add --no-cache tzdata
ENV TZ=Asia/Seoul

# 빌드된 JAR 파일 복사
COPY --from=build /workspace/app/build/libs/*.jar app.jar

# 실행
ENTRYPOINT ["java", "-jar", "app.jar"] 