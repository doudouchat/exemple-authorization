ARG VERSION_TEMURIN=latest
FROM eclipse-temurin:$VERSION_TEMURIN
LABEL maintener=EXEMPLE_TEST
COPY target/*.jar exemple-authorization-integration-resource.jar
ENTRYPOINT ["java","-jar","exemple-authorization-integration-resource.jar"]