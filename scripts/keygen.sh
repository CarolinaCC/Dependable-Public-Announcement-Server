#!/bin/bash

rm *.jks *.cert

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

#store server public key
keytool -export \
        -file server.cert \
        -keystore server.jks \
        -storepass testtest \
        -alias server

#store client public key
keytool -export \
        -file client.cert \
        -keystore client.jks \
        -storepass testtest \
        -alias client