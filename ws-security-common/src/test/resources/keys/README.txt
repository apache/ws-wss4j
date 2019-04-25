Keys generated with:

CA:

openssl req -x509 -newkey rsa:2048 -keyout wss40CAKey.pem -out wss40CA.pem -config ca.config -days 3650
openssl x509 -outform DER -in wss40CA.pem -out wss40CA.crt
keytool -import -file wss40CA.crt -alias wss40CA -keystore wss40CA.jks

=====

Generate the client keypair, make a csr, sign it with the CA key:

keytool -genkey -validity 3650 -alias wss40 -keyalg RSA -keystore wss40.jks
-dname "CN=Colm,OU=WSS4J,O=Apache,L=Dublin,ST=Leinster,C=IE"
keytool -certreq -alias wss40 -keystore wss40.jks -file wss40.cer
openssl ca -config ca.config -policy policy_anything -days 3650 -out wss40.pem -infiles wss40.cer
openssl x509 -outform DER -in wss40.pem -out wss40.crt

Import the CA cert into wss40.jks and import the new signed certificate:

keytool -import -file wss40CA.crt -alias wss40CA -keystore wss40.jks
keytool -import -file wss40.crt -alias wss40 -keystore wss40.jks

=====

Generate the client DSA keypair, make a csr, sign it with the CA key + import
it:

keytool -genkey -validity 3650 -alias wss40DSA -keyalg DSA -keysize 1024 -keystore wss40.jks -dname "CN=Colm,OU=WSS4J,O=Apache,L=Dublin,ST=Leinster,C=IE"
keytool -certreq -alias wss40DSA -keystore wss40.jks -file wss40.cer
openssl ca -config ca.config -policy policy_anything -days 3650 -out wss40.pem -infiles wss40.cer
openssl x509 -outform DER -in wss40.pem -out wss40.crt
keytool -import -file wss40.crt -alias wss40DSA -keystore wss40.jks

=====

Generate the server keypair, make a csr, sign it with the CA key:

keytool -genkey -validity 3650 -alias wss40_server -keyalg RSA -keystore wss40_server.jks -dname "CN=Server,OU=WSS4J,O=Apache,L=Dublin,ST=Leinster,C=IE"
keytool -certreq -alias wss40_server -keystore wss40_server.jks -file wss40_server.cer
openssl ca -config ca.config -policy policy_anything -days 3650 -out wss40_server.pem -infiles wss40_server.cer
openssl x509 -outform DER -in wss40_server.pem -out wss40_server.crt

Import the CA cert into wss40.jks and import the new signed certificate:

keytool -import -file wss40CA.crt -alias wss40CA -keystore wss40_server.jks
keytool -import -file wss40_server.crt -alias wss40_server -keystore wss40_server.jks

=====

1024-bit RSA cert:

keytool -genkey -validity 3650 -alias wss40 -keyalg RSA -keysize 1024 -keystore rsa1024.jks -dname "CN=Colm,OU=WSS4J,O=Apache,L=Dublin,ST=Leinster,C=IE"
keytool -certreq -alias wss40 -keystore rsa1024.jks -file rsa1024.cer
openssl ca -config ca.config -policy policy_anything -days 3650 -out rsa1024.pem -infiles rsa1024.cer
openssl x509 -outform DER -in rsa1024.pem -out rsa1024.crt
keytool -import -file wss40CA.crt -alias wss40CA -keystore rsa1024.jks
keytool -import -file rsa1024.crt -alias wss40 -keystore rsa1024.jks

=====

WSS40CADupl:

cp wss40CA.jks wss40CADupl.jks
keytool -genkey -validity 3650 -alias wss40dupl -keyalg RSA -keystore wss40CADupl.jks -dname "CN=Werner, OU=Apache WSS4J, O=Home, L=Munich, ST=Bayern, C=DE"

=====

wss40exp:

keytool -genkey -validity 1 -alias wss40exp -keyalg RSA -keystore wss40exp.jks -dname "CN=Colm,OU=WSS4J,O=Apache,L=Dublin,ST=Leinster,C=IE"
keytool -certreq -alias wss40exp -keystore wss40exp.jks -file wss40exp.cer
openssl ca -config ca.config -policy policy_anything -days 1 -out wss40exp.pem -infiles wss40exp.cer
openssl x509 -outform DER -in wss40exp.pem -out wss40exp.crt
keytool -import -file wss40CA.crt -alias wss40CA -keystore wss40exp.jks
keytool -import -file wss40exp.crt -alias wss40exp -keystore wss40exp.jks

=====

wss40expca:

Create a CA that will shortly expire:

openssl req -x509 -newkey rsa:2048 -keyout wss40CAKey.pem -out wss40CA.pem -config ca.config -days 1
openssl x509 -outform DER -in wss40CA.pem -out wss40CA.crt
keytool -import -file wss40CA.crt -alias wss40CA -keystore wss40CA.jks

keytool -genkey -validity 3650 -alias wss40expca -keyalg RSA -keystore wss40expca.jks -dname "CN=Colm,OU=WSS4J,O=Apache,L=Dublin,ST=Leinster,C=IE"
keytool -certreq -alias wss40expca -keystore wss40expca.jks -file wss40expca.cer
openssl ca -config ca.config -policy policy_anything -days 3650 -out wss40expca.pem -infiles wss40expca.cer
openssl x509 -outform DER -in wss40expca.pem -out wss40expca.crt
keytool -import -file wss40CA.crt -alias wss40CA -keystore wss40expca.jks
keytool -import -file wss40expca.crt -alias wss40expca -keystore wss40expca.jks

mv wss40CA.jks wss40badcatrust.jks
mv wss40expca.jks wss40badca.jks

=====

wss40rev:

keytool -genkey -validity 3650 -alias wss40rev -keyalg RSA -keystore wss40rev.jks -dname "CN=Colm,OU=WSS4J,O=Apache,L=Dublin,ST=Leinster,C=IE"
keytool -certreq -alias wss40rev -keystore wss40rev.jks -file wss40rev.cer
openssl ca -config ca.config -policy policy_anything -days 3650 -out wss40rev.pem -infiles wss40rev.cer
openssl x509 -outform DER -in wss40rev.pem -out wss40rev.crt

Import the CA cert into wss40.jks and import the new signed certificate

keytool -import -file wss40CA.crt -alias wss40CA -keystore wss40rev.jks
keytool -import -file wss40rev.crt -alias wss40rev -keystore wss40rev.jks

Generate a Revocation list

openssl ca -gencrl -keyfile wss40CAKey.pem -cert wss40CA.pem -out wss40CACRL.pem -config ca.config -crldays 3650
openssl ca -revoke wss40rev.pem -keyfile wss40CAKey.pem -cert wss40CA.pem -config ca.config
openssl ca -gencrl -keyfile wss40CAKey.pem -cert wss40CA.pem -out wss40CACRL.pem -config ca.config -crldays 3650

=====

