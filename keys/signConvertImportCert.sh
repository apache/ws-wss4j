# Sign the server certificate request with the CA using the command 
# (again, "security" is the PEM pass phrase):
openssl ca -config ca.config -policy policy_anything -days 365 -out cert.pem -infiles cert.req

# Convert the server certificate from PEM (plain text format) to DER (binary) format:
openssl x509 -outform DER -in cert.pem -out cert.crt

# import the CA and server certificate into wss4j's keystore (note that 
# importing the server certificate results in the keystore's wss4j 
# certificate being updated with the new signature):
$JAVA_HOME/bin/keytool -import -file ca.crt -keystore wss4j.keystore
$JAVA_HOME/bin/keytool -import -alias wss4jCert -file cert.crt -keystore wss4j.keystore

