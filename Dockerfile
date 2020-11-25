FROM tomcat:9.0.40-jdk8-openjdk
LABEL maintener=EXEMPLE
COPY exemple-authorization-server/target/*.war /usr/local/tomcat/webapps/ExempleAuthorization.war
COPY exemple-authorization-server/src/main/conf/context.xml /usr/local/tomcat/conf/context.xml
COPY exemple-authorization-server/src/main/conf/setenv.sh /usr/local/tomcat/bin/setenv.sh
CMD ["catalina.sh", "run"]