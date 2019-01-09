FROM openjdk:8-jdk-alpine

COPY ./build/libs/hybrid-flow-service-*.jar hybrid-flow-service.jar

ENTRYPOINT ["java", "-jar", "/hybrid-flow-service.jar"]