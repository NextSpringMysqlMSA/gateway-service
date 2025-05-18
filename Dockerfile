# 🔧 빌드 스테이지
FROM amazoncorretto:17-alpine AS build
WORKDIR /workspace/app

COPY gradlew .
COPY gradle gradle
COPY build.gradle .
COPY settings.gradle .

RUN chmod +x ./gradlew
RUN ./gradlew dependencies --no-daemon

COPY src src
RUN ./gradlew clean bootJar -x test --no-daemon
RUN ls -la build/libs/

# 🚀 실행 스테이지
FROM amazoncorretto:17-alpine
WORKDIR /app

RUN apk add --no-cache tzdata
ENV TZ=Asia/Seoul

COPY --from=build /workspace/app/build/libs/*.jar app.jar

ENTRYPOINT ["java", "-Djava.security.egd=file:/dev/./urandom", "-jar", "app.jar"]
