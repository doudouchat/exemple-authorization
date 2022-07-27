ARG VERSION_TOMCAT
FROM tomcat:$VERSION_TOMCAT
LABEL maintener=EXEMPLE
COPY exemple-authorization-launcher/target/*.war /usr/local/tomcat/webapps/ExempleAuthorization.war
COPY exemple-authorization-launcher/src/main/conf/context.xml /usr/local/tomcat/conf/context.xml
COPY exemple-authorization-launcher/src/main/conf/setenv.sh /usr/local/tomcat/bin/setenv.sh
CMD ["catalina.sh", "run"]