[![Codacy Badge](https://api.codacy.com/project/badge/Grade/e64c3c7bccbc433fa68494c1e72d5bb3)](https://app.codacy.com/gh/doudouchat/exemple-authorization?utm_source=github.com&utm_medium=referral&utm_content=doudouchat/exemple-authorization&utm_campaign=Badge_Grade_Settings)
[![build](https://github.com/doudouchat/exemple-authorization/workflows/build/badge.svg)](https://github.com/doudouchat/exemple-authorization/actions)
[![codecov](https://codecov.io/gh/doudouchat/exemple-authorization/graph/badge.svg)](https://codecov.io/gh/doudouchat/exemple-authorization) 

# exemple-authorization

## maven

<p>execute <code>mvn clean install</code></p>

<p>execute with cargo and cassandra <code>mvn clean verify -Pauthorization,it</code></p>

## Docker

<p>build image <code>docker build -t exemple-authorization --build-arg VERSION_TOMCAT=@Tag .</code></p>

<p>exemple build image <code>docker build -t exemple-authorization --build-arg VERSION_TOMCAT=9.0.60-jdk8-openjdk .</code>

## Certificate

keytool -genkeypair -alias mytest -keyalg RSA -keypass mypass -keystore mytest.jks -storepass mypass
