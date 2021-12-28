# Run Instructions
On the repository's root directory

1. ```mvn compile```
```
mvn compile
```
2. ```mvn exec:java@SignalingServer -Dexec.args="<userproxies> <ciphermovies> <keystore> <keystore-password> <truststore> <truststore-password> <tls-conf>"``` For Example:
```
mvn exec:java@SignalingServer -Dexec.args="./src/main/resources/UsersProxies.json ./src/main/resources/CipherMovies.json ./src/main/resources/signalingserver.keystore password ./src/main/resources/catrustedcert.keystore password ./src/main/resources/tls.json"
```
3. ```mvn exec:java@StreamingServer -Dexec.args="<keystore> <keystore-password> <truststore> <truststore-password> <tls-conf> <dtls-conf>"``` For Example:
```
mvn exec:java@StreamingServer -Dexec.args="./src/main/resources/streamingserver.keystore password ./src/main/resources/catrustedcert.keystore password ./src/main/resources/tls.json ./src/main/resources/dtls.json"
```
4. ```mvn exec:java@ProxyBox -Dexec.args="<movieId> <username> <password> <ProxyInfo> <keystore> <keystore-password> <truststore> <truststore-password> <tls-conf> <dtls-conf>"``` For Example:
```
mvn exec:java@ProxyBox -Dexec.args="monsters username password ./src/main/resources/ProxInfo ./src/main/resources/proxybox.keystore password ./src/main/resources/catrustedcert.keystore password ./src/main/resources/tls.json ./src/main/resources/dtls.json"
```