
* Apache WSS4J *

The Apache WSS4J© project provides a Java implementation of the primary
security standards for Web Services, namely the OASIS Web Services Security
(WS-Security) specifications from the OASIS Web Services Security TC. WSS4J
provides an implementation of the following WS-Security standards:

    SOAP Message Security 1.1
    Username Token Profile 1.1
    X.509 Certificate Token Profile 1.1
    SAML Token Profile 1.1
    Basic Security Profile 1.1

Apache WSS4J, Apache, and the Apache feather logo are trademarks of The Apache
Software Foundation. 

The master link to WSS4J: http://ws.apache.org/wss4j/

* Crypto Notice *

   This distribution includes cryptographic software.  The country in
   which you currently reside may have restrictions on the import,
   possession, use, and/or re-export to another country, of
   encryption software.  BEFORE using any encryption software, please
   check your country's laws, regulations and policies concerning the
   import, possession, or use, and re-export of encryption software, to
   see if this is permitted.  See <http://www.wassenaar.org/> for more
   information.

   The U.S. Government Department of Commerce, Bureau of Industry and
   Security (BIS), has classified this software as Export Commodity
   Control Number (ECCN) 5D002.C.1, which includes information security
   software using or performing cryptographic functions with asymmetric
   algorithms.  The form and manner of this Apache Software Foundation
   distribution makes it eligible for export under the License Exception
   ENC Technology Software Unrestricted (TSU) exception (see the BIS
   Export Administration Regulations, Section 740.13) for both object
   code and source code.

   The following provides more details on the included cryptographic
   software:

   Apache Santuario : http://santuario.apache.org/
   Apache WSS4J     : http://ws.apache.org/wss4j/
   Bouncycastle     : http://www.bouncycastle.org/

* Test Requirements *

The WSS4J unit tests use STRONG encryption. The default encryption algorithms
included in a JRE is not adequate for these samples. The Java Cryptography
Extension (JCE) Unlimited Strength Jurisdiction Policy Files available on
Oracle's JDK download page[1] *must* be installed for the tests to work. If
you get errors about invalid key lengths, the Unlimited Strength files are not
installed.

[1] http://www.oracle.com/technetwork/java/javase/downloads/index.html

Note that for JDK 1.5 the tests require that xml-apis and xercesImpl be 
available in an "endorsed" subdirectory.

