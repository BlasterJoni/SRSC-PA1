# Run Instructions
On the repository's root directory

1. ```mvn compile```
```
mvn compile
```
2. ```mvn exec:java@SignalingServer -Dexec.args="<keystore> <keystore-password> <userproxies> <ciphermovies>"``` For Example:
```
mvn exec:java@SignalingServer -Dexec.args="./src/main/resources/signalingserver.keystore password ./src/main/resources/UsersProxies.json ./src/main/resources/CipherMovies.json"
```
3. ```mvn exec:java@StreamingServer -Dexec.args="<keystore> <keystore-password>"``` For Example:
```
mvn exec:java@StreamingServer -Dexec.args="./src/main/resources/streamingserver.keystore password"
```
4. ```mvn exec:java@ProxyBox -Dexec.args="<movieId> <username> <password> <keystore> <keystore-password> <ProxyInfo>"``` For Example:
```
mvn exec:java@ProxyBox -Dexec.args="monsters username password ./src/main/resources/proxybox.keystore password ./src/main/resources/ProxInfo"
```