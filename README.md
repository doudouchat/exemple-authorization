[![Build Status](https://travis-ci.com/doudouchat/exemple-authorization.svg?branch=master)](https://travis-ci.org/doudouchat/exemple-authorization) 

# exemple-authorization

## maven

<p>execute <code>mvn clean install</code></p>

<p>execute with cargo and cassandra <code>mvn clean verify -Pauthorization,it</code></p>

## Docker

<ol>
<li>docker build -t exemple-authorization .</li>
</ol>

<ol>
<li>docker-compose up -d authorization</li>
</ol>

## Certificate

keytool -genkeypair -alias mytest -keyalg RSA -keypass mypass -keystore mytest.jks -storepass mypass