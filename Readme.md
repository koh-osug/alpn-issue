# Summary

Project demonstrating [Conscrypt APLN issue](https://github.com/google/conscrypt/issues/1003) 

The [Java SSLEngine](https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/net/ssl/SSLEngine.html#getApplicationProtocol())
defines three states: `null`, an empty response and a string for the application protocol returned with `getApplicationProtocol`.
Conscrypts returns `null` also if no ALPN extension is included in the TLS handshake.


# Test Issue

~~~
mvn test
~~~