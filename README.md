[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=doudouchat_exemple-authorization&metric=alert_status)](https://sonarcloud.io/dashboard?id=doudouchat_exemple-authorization)
[![build](https://github.com/doudouchat/exemple-authorization/workflows/build/badge.svg)](https://github.com/doudouchat/exemple-authorization/actions)
[![codecov](https://codecov.io/gh/doudouchat/exemple-authorization/graph/badge.svg)](https://codecov.io/gh/doudouchat/exemple-authorization) 

# exemple-authorization

## maven

<p>execute <code>mvn clean install</code></p>

<p>execute with docker and cassandra <code>mvn clean verify -Pauthorization,it</code></p>

## Docker

<p>build image <code>docker build -t exemple-authorization --build-arg VERSION_TOMCAT=@Tag .</code></p>

<p>exemple build image <code>docker build -t exemple-authorization --build-arg VERSION_TOMCAT=9.0.60-jdk8-openjdk .</code>

## Certificate

keytool -genkeypair -alias mytest -keyalg RSA -keypass mypass -keystore mytest.jks -storepass mypass
