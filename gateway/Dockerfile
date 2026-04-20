# Estágio de build com Java 21 (LTS)
FROM maven:3.9-eclipse-temurin-21 AS builder

WORKDIR /build

COPY pom.xml .
COPY .mvn .mvn
COPY mvnw .
RUN chmod +x mvnw
COPY src src


RUN ./mvnw clean package -DskipTests

FROM eclipse-temurin:21-jre-alpine

RUN apk add --no-cache wget

WORKDIR /app
COPY --from=builder /build/target/*.jar app.jar

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget --spider -q http://localhost:8080/actuator/health

ENTRYPOINT ["java", "-jar", "app.jar"]