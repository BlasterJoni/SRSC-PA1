#/bin/sh

#
echo "------------------------------------------------------------------------"
echo "Establishment of the CA Root and CA Root Level Certificate"
echo "------------------------------------------------------------------------"
# 1) To begin, we first generate a key pair which will be used as the CA,
#    the private key will be used to sign the certificate it issues.

keytool -genkeypair -keyalg RSA -alias root -keystore root.jks -dname "CN=Root CA" -storepass password -keypass password -ext bc=ca:true

keytool -export -alias root -keystore root.jks -storepass password -file root.crt

echo "CA generated a public-private pair, stored in keystore root.jks"
echo "and a CA root certificate is stored in root.crt"
echo "Root CA ESTABLISHED"
echo ""
echo "---------------------------------------------------------"
echo "The Root CA Certificate"
echo "---------------------------------------------------------"
keytool -printcert -file root.crt
echo "---------------------------------------------------------"

echo "------------------------------------------------------------------------"
echo "Now, can import the CA root as a trusted certificate"
echo "Let's store it in a catrustedcert keystore"
echo "------------------------------------------------------------------------"
# KEYSTORE QUE SE VAI USAR COMO TRUST
keytool -import -alias root -file root.crt -keystore catrustedcert.jks -storepass password -keypass password


echo "------------------------------------------------------------------------"
echo "Intermediate CA Certificate"
echo "------------------------------------------------------------------------"
# 2) Then, generate a key pair where the certificate of it will be signed
#    by the CA above (itself).
#    So this an selfigned / selfissued  certificate

keytool -genkeypair -keyalg RSA -alias ca -keystore ca.jks -dname "CN=Intermediate CA" -storepass password -keypass password -ext bc=ca:true

#  3) Next, a certificate request for the "CN=ca" certificate needs to be
#  created.

keytool -certreq -keystore ca.jks -storepass password -alias ca -file ca.csr

#  4) Now creating the certificate with the certificate request generated
#  above.

keytool -gencert -keystore root.jks -storepass password -alias root -infile ca.csr -outfile ca.crt -ext bc=ca:true

#  5) An output certificate file ca.crt will be created. Now let's see
#  what its content is.

echo
echo "---------------------------------------------------------"
echo "The Intermediate CA Certificate"
echo "---------------------------------------------------------"
keytool -printcert -file ca.crt
echo "---------------------------------------------------------"

echo "------------------------------------------------------------------------"
echo "Proxy Box Certificate"
echo "------------------------------------------------------------------------"
# 2) Then, generate a key pair where the certificate of it will be signed
#    by the CA above (itself).
#    So this an selfigned / selfissued  certificate


keytool -genkeypair -keyalg RSA -alias tls -keystore proxybox.jks -dname "CN=Proxy Box" -storepass password -keypass password

#  3) Next, a certificate request for the "CN=Proxy Box" certificate needs to be
#  created.

keytool -certreq -keystore proxybox.jks -storepass password -alias tls -file proxybox.csr

#  4) Now creating the certificate with the certificate request generated
#  above.

keytool -gencert -keystore ca.jks -storepass password -alias ca -infile proxybox.csr -outfile proxybox.crt

#  5) An output certificate file proxybox.crt will be created. Now let's see
#  what its content is.

echo
echo "---------------------------------------------------------"
echo "The Proxy Box Certificate"
echo "---------------------------------------------------------"
keytool -printcert -file proxybox.crt
echo "---------------------------------------------------------"

echo "------------------------------------------------------------------------"
echo "Signaling Server Certificate"
echo "------------------------------------------------------------------------"
# 2) Then, generate a key pair where the certificate of it will be signed
#    by the CA above (itself).
#    So this an selfigned / selfissued  certificate


keytool -genkeypair -keyalg RSA -alias tls -keystore signalingserver.jks -dname "CN=Signaling Server" -storepass password -keypass password

#  3) Next, a certificate request for the "CN=Signaling Server" certificate needs to be
#  created.

keytool -certreq -keystore signalingserver.jks -storepass password -alias tls -file signalingserver.csr

#  4) Now creating the certificate with the certificate request generated
#  above.

keytool -gencert -keystore ca.jks -storepass password -alias ca -infile signalingserver.csr -outfile signalingserver.crt

#  5) An output certificate file signalingserver.crt will be created. Now let's see
#  what its content is.

echo
echo "---------------------------------------------------------"
echo "The Signaling Server Certificate"
echo "---------------------------------------------------------"
keytool -printcert -file signalingserver.crt
echo "---------------------------------------------------------"

echo "------------------------------------------------------------------------"
echo "Streaming Server Certificate"
echo "------------------------------------------------------------------------"
# 2) Then, generate a key pair where the certificate of it will be signed
#    by the CA above (itself).
#    So this an selfigned / selfissued  certificate


keytool -genkeypair -keyalg RSA -alias tls -keystore streamingserver.jks -dname "CN=Streaming Server" -storepass password -keypass password

#  3) Next, a certificate request for the "CN=Streaming Server" certificate needs to be
#  created.

keytool -certreq -keystore streamingserver.jks -storepass password -alias tls -file streamingserver.csr

#  4) Now creating the certificate with the certificate request generated
#  above.

keytool -gencert -keystore ca.jks -storepass password -alias ca -infile streamingserver.csr -outfile streamingserver.crt

#  5) An output certificate file streamingserver.crt will be created. Now let's see
#  what its content is.

echo
echo "---------------------------------------------------------"
echo "The Streaming Server Certificate"
echo "---------------------------------------------------------"
keytool -printcert -file streamingserver.crt
echo "---------------------------------------------------------"

echo
echo "------------------------------------------------------------------------"
echo "Create the Certificate Chain CA-Root:Leaf"
echo "------------------------------------------------------------------------"

#cat root.crt > certchain.crt

#keytool -import -file certchain.crt -keystore root.jks -alias root -storepass password -keypass password

#cat root.crt ca.crt >> ca.crt

#keytool -import -file ca.crt -keystore ca.jks -alias ca -storepass password -keypass password

cat root.crt ca.crt proxybox.crt >> proxybox.crt
keytool -printcert -file proxybox.crt
# keystore que vamos usar como key
keytool -import -file proxybox.crt -keystore proxybox.jks -alias tls -storepass password -keypass password

cat root.crt ca.crt signalingserver.crt >> signalingserver.crt
keytool -printcert -file signalingserver.crt
# keystore que vamos usar como key
keytool -import -file signalingserver.crt -keystore signalingserver.jks -alias tls -storepass password -keypass password

cat root.crt ca.crt streamingserver.crt >> streamingserver.crt
keytool -printcert -file streamingserver.crt
# keystore que vamos usar como key
keytool -import -file streamingserver.crt -keystore streamingserver.jks -alias tls -storepass password -keypass password

