# mongosql-java-auth
A MySQL authentication plugin that implements the client-side of MongoDB-supported authentication mechanisms, including

* SCRAM-SHA-1
* PLAIN

## Usage

Include this library in the classpath.  The Maven coordinates are:

    <dependency>
        <groupId>org.mongodb</groupId>
        <artifactId>mongosql-auth</artifactId>
        <version>1.0.0</version>
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
    
## Notes

* The SCRAM-SHA-1 mechanism hashes the passwords in the client plugin, so it can be used on an unencrypted connection without exposing 
the password.
* The PLAIN mechanism sends the password in cleartext, so should only be used on an encrypted connection, though this is not enforced.


