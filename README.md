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

From the scripts directory:\
`$./start.sh f` where f is the number of faults to tolerate\
This starts the 3*f+1 servers, starting on port 9000. It also generates client and server keystores and places them in the appropriate directories\
You can also run `$./start-fault.sh f`, which starts 2*f+1 servers, thus displaying the systems fault tolerance\
Start a client with `./client.sh f`. Stop the client with Ctrl+c

Since servers are started in the background, to stop the system we recommend using `killall java`.

The `library` module has the client-front end, which is used by the client application in the `client` module.\
You can use the client application to test the functioning of the system. It's only limitation is that posts, references and files may not include spaces.\
Alternatively, you can have a look at our test suite, which can be found in two modules:\
The `common` module tests that the domain of the application is correct and that the correct exceptions are always thrown.

The `utils` module tests implements the algorithms for authenticated perfect links and byzantine tolerant shared memory and testes them

The `server` module test that the server performs all the operations correctly, that the system can handle concurrent requests and maintain a consistent state, and the properties fault tolerance properties of the system.


You can find the report in the docs folder


