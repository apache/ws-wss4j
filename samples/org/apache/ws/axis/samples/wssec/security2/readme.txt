The security sample demonstrates how to use the Axis architecture to
add  digital signatures to your application.

To run the sample,

1. Set up your CLASSPATH.
2. Start an Axis server.
3. Install the server side handler.
4. Run the client application.


1. Set up your CLASSPATH.
   The CLASSPATH must contain:  an XML parser (ie., Xerces), JUnit
   (www.junit.org), xmlsec.jar (xml.apache.org/security/index.html),
   xalan.jar (comes with xmlsec.jar, or xml.apache.org/xalan-j), log4j.jar
   (comes with xmlsec.jar, or jakarta.apache.org/log4j), xml-apis.jar (comes
   with xmlsec.jar), jce-jdk13-113.jar (www.bouncycastle.org), all the jars
   in the lib directory, and the directory containing the samples 
   subdirectory.

1.5.  NOTE:  If the build you have wasn't built with security turned on, you
      will have to build this sample by hand.  From the samples/security
      directory, simply run:
          javac *.java

2. Start an Axis server.
   To run the sample, you will first need to run a server.  To run a very
   simple server you could run, in a separate window:
       java org.apache.axis.transport.http.SimpleAxisServer -p 8080

3. Install the server side handler.
   You need to install the server's digital signature handler.  To do this:
       java org.apache.axis.client.AdminClient samples/org.apache.ws.security.wssec/security2/securitydeploy.wsdd

4. Run the client application.
   Finally, to run the client, run:
       java org.apache.ws.security.wssec.security2.Client -x

This sample also allows you to setup an Axis server to allow transparent
digital signature of all SOAP messages being processed by the server.  To
enable this, in addition to step 3 above, do the following:

3.3. Install the client side handler.
     On the client side, ClientSigningHandler is installed in the global
     request chain.  You must run the following command two directories above
     the security sample directory:
         java org.apache.axis.utils.Admin client samples/org.apache.ws.security.wssec/security2/clientsecuritydeploy.wsdd

3.5. Install the server side handler: On the server side, LogHandler is
     installed in the global request chain.  You must run the following
     command two directories above the security sample directory:
         java org.apache.axis.client.AdminClient samples/org.apache.ws.security.wssec/security2/serversecuritydeploy.wsdd
