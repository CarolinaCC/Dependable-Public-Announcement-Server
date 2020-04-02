# Dependable-Public-Announcement-Server
The emergence of fake news and the need for trusted sources of information requires an information system where relevant
 public information and facts can be posted, tracked and verified.

## Group 18
Catarina Guerreiro Gomes Pedreira 87524\
Carolina Maria Da Cunha Carreira 87641\
Miguel Veloso Barros 87691

Requirements:

Java 11\
Apache Maven

Steps to Run:

From the project root directory:\
`$ mvn clean install`
This installs all the dependencies and runs the tests

From the server directory:\
`$mvn compile exec:java`\
This starts the server on port 9000 with the keystore currently present.

You can also generate a key store with the script `keygen.sh` present in the `scripts` directory.\
The Keys present in the client keystore are as follow:\
alias: client-1 password: client-1-password\
alias: client-1 password: client-1-password\
alias: client-1 password: client-1-password\
alias: server

The Keys present in the client keystore are as follow:\
alias: server password: server-password

The server is pre populated with posts and users to remove them just remove the file `server/src/main/resources/save/save.json`.\
The `library` module has the client-front end, which is used by the client application in the `client` module.\
You can use the client application to test the functioning of the system. It's only limitation is that posts, references and files may not include spaces.\
Alternatively, you can have a look at our test suite, which can be found in two modules:\
The `common` module tests that the domain of the application is correct and that the correct exceptions are always thrown.

The `server` module test that the server performs all the operations correctly. 
It also tests that the server recovers correctly from a crash (PersistentManagerTest) 
And finally it tests that the server can handle concurrent requests and maintain a consistent state.

There are three versions of the server that were developed sequentially on top of each other. 
The ServiceDPASImpl is the base server without dependability guarantees.
The ServiceDPASPersistentImpl builds on the previous by guaranteeing persistence in the presence of faults
The ServiceDPASSafeImpl builds on the previous by ensuring the freshness of the requests received.


