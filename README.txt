Here is the master link to all Apache Web Service projects:

http://ws.apache.org/

What is WSS4J?

Apache WSS4J is an implementation of the OASIS Web Services Security 
(WS-Security) from OASIS Web Services Security TC. WSS4J is a primarily
a Java library that can be used to sign and verify SOAP Messages with 
WS-Security information. WSS4J will use Apache Axis and Apache XML-Security
projects and will be interoperable with JAX-RPC based server/clients 
and .NET server/clients.

WSS4J implements

 * OASIS Web Serives Security: SOAP Message Security 1.0 Standard 200401, 
   March 2004
 * Username Token profile V1.0
 * X.509 Token Profile V1.0

WSS4J can also be configured to emulate previous WSS spec implementations
with older namespaces, such as WebSphere 5.1 and WebLogic 8.1 SP2.

WS-Security Features

WSS4J can generate and process the following SOAP Bindings:

    o XML Security
         + XML Signature
         + XML Encryption
    o Tokens
         + Username Tokens
         + Timestamps
         + SAML Tokens

WSS4J supports X.509 binary certificates and certificate paths.

The master link to WSS4J:
http://ws.apache.org/wss4j/

There is also a Wiki concering Apache WS projects and WSS4J as one
of the WS sub-projects:
    http://wiki.apache.org/ws/
    http://wiki.apache.org/ws/FrontPage/WsFx


TODO: describe parts Trust, Conversation

Required software

To work with WSS4J you need additional software. Most of
the software is also needed by your SOAP base system, e.g.
Apache Axis. To implement the Web Service Security (WSS) parts
specific software is required such. See below.

addressing-1.0.jar
    This jar contains the implementation of WS-Adressing, required
    by WSS4J Trust.

    See: http://ws.apache.org/addressing/

axis-1.2.1.jar
axis-ant-1.2.1.jar
axis-jaxrpc-1.2.1.jar
axis-saaj-1.2.1.jar
    These jars contain the Apache Axis base software. They implement
    the basic SOAP processing, deployment, WSDL to Java, Java to WSDL
    tools and a lot more. Plase refer to a Axis documentation how to
    setup Axis. You should be familiar with Axis, its setup, and 
    deployment methods before you start with any WSS4J functions.
    
    See: http://ws.apache.org/axis/

bcprov-jdk13-128.jar
    This is the BouncyCastle library that implements all necessary
    encryption, hashing, certifcate, and keystore functions. Without
    this fanatstic library WSS4J wouldn't work at all.
    
    See: http://www.bouncycastle.org/
    
commons-codec-1.3.jar
commons-discovery-0.2.jar
commons-httpclient-3.0-rc2.jar
commons-logging-1.0.4.jar
    These jars are from the Commons project and provide may useful 
    funtions, such as Base64 encoding/decoding, resource lookup,
    and much more. Please refer to the commons project to get more
    information.
    
    The master link for the commons project:
    http://jakarta.apache.org/commons/index.html

junit-3.8.1.jar
    The famous unit test library. Required if you like to build WSS4J
    from source and run the unit tests.
    
    See: http://www.junit.org/
    
log4j-1.2.9.jar
    The logging library. Required to control the logging, error 
    reporting and so on.
    
    See: http://logging.apache.org/

opensaml-1.0.1.jar
    The SAML implemetation used by WSS4J to implement the SAML profile.
    
    See: http://www.opensaml.org/

wsdl4j-1.5.1.jar
    The WSDL parsing functions, required by Axis tools to read and
    parse WSDL.
    
    See: http://ws.apache.org/axis/  under related projects
    
xalan-2.6.0.jar
    Library that implements XML Path Language (XPath) and XSLT. The XML 
    Security implementation needs several functions of Xalan XPath.
   
    See: http://xml.apache.org/xalan-j/
   
xmlsec-1.2.1.jar
    This library implements the XML-Signature Syntax and Processing and
    the XML Encryption Syntax and Processing specifications of the W3C. Thus
    they form one of the base foundations of WSS4J.  
    
    See: http://xml.apache.org/security/
    
dom3-xercesImpl-2_6_2.jar
dom3-xml-apis-2_6_2.jar
    The XML parser implementation. Required by anybody :-) .

    See: http://xml.apache.org/xerces2-j/
