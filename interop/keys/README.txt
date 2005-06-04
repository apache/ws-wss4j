- Certificates and keys are from the Gartner WSS interop show. 
- Passwords for every private key is 'password' (no quotes). 
- Bob identity for service and Alice identity for client.
- The ca.pfx files contains cert and private key for intermediary CA 
  used to issue Alice and Bob certificates and root.pfx contains cert 
  and private key for root CA used to issue the intermediary CA 
  certificate.
- Conversion tips are from http://mark.foster.cc/kb/openssl-keytool.html  

java -classpath org.mortbay.jetty-5.1.4rc0.jar org.mortbay.util.PKCS12Import alice.pfx alice.jks
java -classpath org.mortbay.jetty-5.1.4rc0.jar org.mortbay.util.PKCS12Import bob.pfx bob.jks
java -classpath org.mortbay.jetty-5.1.4rc0.jar org.mortbay.util.PKCS12Import ca.pfx ca.jks
java -classpath org.mortbay.jetty-5.1.4rc0.jar org.mortbay.util.PKCS12Import root.pfx root.jks

keytool -export -alias 1 -keystore root.jks -file root.crt
keytool -export -alias 1 -keystore bob.jks -file bob.crt
keytool -export -alias 1 -keystore alice.jks -file alice.crt
keytool -export -alias 1 -keystore ca.jks -file ca.crt

keytool -import -keystore interop2.jks -import -trustcacerts -alias root -file root.crt
keytool -import -keystore interop2.jks -import -trustcacerts -alias ca -file ca.crt
keytool -import -keystore interop2.jks -import -trustcacerts -alias bob -file bob.crt
keytool -import -keystore interop2.jks -import -trustcacerts -alias alice -file alice.crt

keytool -list -v -keystore interop2.jks