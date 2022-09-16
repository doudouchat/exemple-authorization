ARG VERSION_OPENJDK
FROM openjdk:$VERSION_OPENJDK
LABEL maintener=EXEMPLE_TEST
COPY target/*.jar exemple-authorization-integration-resource.jar
ENTRYPOINT ["java","-jar","exemple-authorization-integration-resource.jar"]