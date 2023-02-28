# AWS CloudHSM Example Mutual TLS Client

This is a sample project to demonstrate an HTTP client configured to negotiate a Mutual TLS connection - backed by a 
key stored on the HSM - to BadSSL.com and print the resulting page content to the console.

## Setup

The library requires the JCE cloud HSM library to have been installed and configured on the local machine. The JCE provider JAR then needs to be copied from the installation direction to the lib directory in this project.

If credentials need provided outside of environment variables then add a line equivalent to the following in MutualTlsExample#main
```java
provider.login(null, new UsernamePasswordAuthHandler("my_hsm_username", "my_hsm_users_password".toCharArray()))
```

The BadSSL client certificate needs to be downloaded from https://badssl.com/download/, installed into the HSM with the
alias `badssl`, and shared with the user the JCE is configured to authenticate as.

## Execution

Execute the `MutualTlsExample` class through your IDE.

If everything works as expected an HTML page should be printed to the console with the title `client.badssl.com`