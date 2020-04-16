#!/bin/bash
let i=3*$1+1

./keygen.sh $i

mv client.jks ../client/src/main/resources
mv server.jks ../server/src/main/resources

for j in $(seq 1 1 $i) 
do
       let k=9000+$j	
	cd ../server
	mvn compile exec:java -Dserver.publicKeyAlias=server-$j \
		-Dserver.persistenceFile=src/main/resources/save/save-$j.json \
		-Dserver.PrivateKeyPassword=server-$j-password \
		-Dserver.Id=$j \
	       -Dserver.port=$k	\
	       &
	cd ../scripts
done
