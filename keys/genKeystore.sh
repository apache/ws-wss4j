#
# Clean out the server and client keystores
# rm wss4j.keystore

# Generate the key that will be used for wss4j
# (use security as the password)
# $JAVA_HOME/bin/keytool -genkey -alias wss4jCert -keyalg RSA -keystore wss4j.keystore -dname "CN=wernerd,OU=WSS4J,O=Apache,L=Munich,ST=Bayern,C=DE"
$JAVA_HOME/bin/keytool -genkey -alias wss4jCertDSA -keystore wss4j.keystore -dname "CN=wernerdDSA,OU=WSS4J,O=Apache,L=Munich,ST=Bayern,C=DE"

