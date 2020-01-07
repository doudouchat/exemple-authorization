FROM tomcat:8.5.32-jre8
LABEL maintener=EXEMPLE
COPY target/*.war /usr/local/tomcat/webapps/ExempleAuthorization.war
COPY src/main/conf/context.xml /usr/local/tomcat/conf/context.xml
COPY src/main/conf/setenv.sh /usr/local/tomcat/bin/setenv.sh
CMD ["catalina.sh", "run"]