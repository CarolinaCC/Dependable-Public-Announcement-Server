#!/bin/bash

rm *.jks 

#generate Server KeyStore
keytool -genkeypair \
        -alias server \
        -dname "CN=localhost" \
        -keyalg RSA \
        -keysize 4096 \
        -validity 365 \
        -storepass server-password \
        -keystore server.jks \
        -storetype jks \
        -keypass server-password

#generate client KeyStore
keytool -genkeypair \
        -alias client-1 \
        -dname "CN=localhost" \
        -keyalg RSA \
        -keysize 4096 \
        -validity 365 \
        -storepass client-password \
        -keystore client.jks \
        -storetype jks \
        -keypass client-1-password


#generate second client key
keytool -genkeypair \
        -alias client-2 \
        -dname "CN=localhost" \
        -keyalg RSA \
        -keysize 4096 \
        -validity 365 \
        -storepass client-password \
        -keystore client.jks \
        -storetype jks \
        -keypass client-2-password


#generate client KeyStore
keytool -genkeypair \
        -alias client-3 \
        -dname "CN=localhost" \
        -keyalg RSA \
        -keysize 4096 \
        -validity 365 \
        -storepass client-password \
        -keystore client.jks \
        -storetype jks \
        -keypass client-3-password


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
