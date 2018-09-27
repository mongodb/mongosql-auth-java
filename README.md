# mongosql-java-auth
A MySQL authentication plugin that implements the client-side of MongoDB-supported authentication mechanisms, including

* SCRAM-SHA-1
* SCRAM-SHA-256
* PLAIN
* GSSAPI (Kerberos)

## Usage

Include this library in the classpath.  The Maven coordinates are:

    <dependency>
        <groupId>org.mongodb</groupId>
        <artifactId>mongosql-auth</artifactId>
        <version>1.1.0</version>
    </dependency>

Next, add a reference to the authentication plugin via the MySQL connection string:

    jdbc:mysql://127.0.0.1:3307?useSSL=false&authenticationPlugins=org.mongodb.mongosql.auth.plugin.MongoSqlAuthenticationPlugin

Optionally, specify the authentication mechanism via a query parameter on the user name.  The default mechanism is SCRAM-SHA-1.  
For example:

    username?mechanism=PLAIN   

Optionally, specify the authentication source via a query parameter on the user name.  The default source is "admin" for 
SCRAM-SHA-1 and MONGODB-CR, and "$external" for PLAIN and GSSAPI. For example:

    username?source=somedb

Optionally, if using GSSAPI, specify the service name via a query parameter on the user name.  The default service name is "mongosql". For example:

    username?mechanism=GSSAPI&serviceName=myservicename

SCRAM-SHA-256 is now a supported authentication mechanism.
    
## Notes

* The SCRAM-SHA-1 and SCRAM-SHA-256 mechanisms hash the passwords in the client plugin, so it can be used on an unencrypted connection without exposing the password (however, subsequent communication over that channel will be unencrypted).
* The PLAIN mechanism sends the password in cleartext, so should only be used on an encrypted connection.
* The GSSAPI mechanism sends the end-user's credentials to the mongosqld - allowing mongosqld to reuse those credentials to access MongoDB.
