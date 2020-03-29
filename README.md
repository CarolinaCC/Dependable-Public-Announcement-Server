# Dependable-Public-Announcement-Server
The emergence of fake news and the need for trusted sources of information requires an information system where relevant public information and facts can be posted, tracked and verified.

## Group 18
Catarina Guerreiro Gomes Pedreira 87524\
Carolina Maria Da Cunha Carreira 87641\
Miguel Veloso Barros 87691\

Requirements:

Java 11\
Apache Maven\

Steps to Run:

From the project root directory:\
`$ mvn clean install`
This installs all the dependencies and runs the tests

From the server directory:\
`$mvn compile exec:java`\
This starts the server on port 9000 with the keystore currently present.

You can also generate a key store with the script `keygen.sh` present in the `scripts` directory.\
The server is pre populated with posts and users to remove them just remove the file `server/src/main/resources/save/save.json`.\


