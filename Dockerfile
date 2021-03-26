FROM openjdk:17-oraclelinux8
MAINTAINER Shreyas Dange

COPY ./build/libs/*.jar /app/spring-security-rbac.jar
EXPOSE 8080/tcp

ENTRYPOINT ["java", "-Dspring.profiles.active=docker","-jar", "/app/spring-security-rbac.jar"]