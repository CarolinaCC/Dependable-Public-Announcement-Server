#!/bin/bash

rm *.jks *.der *.pem *.cert

#generate Server KeyStore
keytool -genkey \
        -alias server \
        -dname "CN=localhost" \
        -keyalg RSA \
        -validity 365 \
        -storepass testtest \
        -keystore server.jks

#generate client KeyStore
keytool -genkey \
        -alias client \
        -dname "CN=localhost" \
        -keyalg RSA \
        -validity 365 \
        -storepass testtest \
        -keystore client.jks

#store server public certificate
keytool -export \
        -file server.der \
        -keystore server.jks \
        -storepass testtest \
        -alias server

#store client public certificate
keytool -export \
        -file client.der \
        -keystore client.jks \
        -storepass testtest \
        -alias client
