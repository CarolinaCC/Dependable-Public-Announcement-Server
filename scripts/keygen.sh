#!/bin/bash

rm *.jks 

#generate Server KeyStore
keytool -genkeypair \
        -alias server \
        -dname "CN=localhost" \
        -keyalg RSA \
        -validity 365 \
        -storepass server-password \
        -keystore server.jks

#generate client KeyStore
keytool -genkeypair \
        -alias client \
        -dname "CN=localhost" \
        -keyalg RSA \
        -validity 365 \
        -storepass client-password \
        -keystore client.jks

#store server public certificate
keytool -exportcert \
        -file server.der \
        -keystore server.jks \
        -storepass server-password \
        -alias server

#store server certificate in client keystore
keytool -importcert \
	-file server.der \
	-keystore client.jks \
	-storepass client-password \
	-noprompt \
	-alias server

rm server.der
