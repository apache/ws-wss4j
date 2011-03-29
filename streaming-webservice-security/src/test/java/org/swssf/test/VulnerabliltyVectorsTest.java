/**
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.swssf.test;

import org.apache.ws.security.handler.WSHandlerConstants;
import org.swssf.ext.Constants;
import org.swssf.ext.SecurePart;
import org.swssf.ext.SecurityProperties;
import org.swssf.ext.WSSecurityException;
import org.swssf.policy.PolicyEnforcer;
import org.swssf.policy.PolicyEnforcerFactory;
import org.swssf.policy.PolicyInputProcessor;
import org.swssf.policy.secpolicy.WSSPolicyException;
import org.swssf.test.utils.CustomW3CDOMStreamReader;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.stream.XMLStreamException;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Properties;

/**
 * @author $Author: giger $
 * @version $Revision: 272 $ $Date: 2010-12-23 14:30:56 +0100 (Thu, 23 Dec 2010) $
 */
public class VulnerabliltyVectorsTest extends AbstractTestBase {

    /**
     * Tests if the framework is vulnerable to recursive key references
     *
     * @throws Exception
     */
    @Test
    public void testRecursiveKeyReferencesDOS() throws Exception {
        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

        String action = WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPT;
        Properties properties = new Properties();
        properties.setProperty(WSHandlerConstants.SIGNATURE_PARTS, "{Element}{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp;{Element}{http://schemas.xmlsoap.org/soap/envelope/}Body;");
        Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

        XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey");
        Element encryptedKeyElement = (Element) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
        encryptedKeyElement.removeAttribute("Id");
        encryptedKeyElement.setAttribute("Id", "2");

        xPathExpression = getXPath(".//dsig:X509Data");
        Element keyIdentifierElement = (Element) xPathExpression.evaluate(encryptedKeyElement, XPathConstants.NODE);
        Element securityTokenReferenceElement = (Element) keyIdentifierElement.getParentNode();
        securityTokenReferenceElement.removeChild(keyIdentifierElement);
        //wsse:Reference xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" URI="#EncKeyId-1483925398"/>
        Element referenceElement = securedDocument.createElementNS(Constants.TAG_wsse_Reference.getNamespaceURI(), Constants.TAG_wsse_Reference.getLocalPart());
        referenceElement.setAttribute("URI", "#1");
        securityTokenReferenceElement.appendChild(referenceElement);

        Element clonedEncryptedElement = (Element) encryptedKeyElement.cloneNode(true);
        clonedEncryptedElement.removeAttribute("Id");
        clonedEncryptedElement.setAttribute("Id", "1");

        xPathExpression = getXPath(".//wsse:Reference");
        Element newReferenceElement = (Element) xPathExpression.evaluate(clonedEncryptedElement, XPathConstants.NODE);
        newReferenceElement.removeAttribute("URI");
        newReferenceElement.setAttribute("URI", "#2");

        Element securityHeaderNode = (Element) encryptedKeyElement.getParentNode();
        securityHeaderNode.insertBefore(clonedEncryptedElement, encryptedKeyElement);

        SecurityProperties securityProperties = new SecurityProperties();
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());
        securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        try {
            Document document = doInboundSecurity(securityProperties, new CustomW3CDOMStreamReader(securedDocument));
            Assert.fail("Expected XMLStreamException");
        } catch (XMLStreamException e) {
            Throwable throwable = e.getCause();
            Assert.assertNotNull(throwable);
            Assert.assertTrue(throwable instanceof WSSecurityException);
            //we expect a "No SecurityToken found" since WSS says that a token must be declared before use.
            //the declare before use is in the nature of streaming xml-security and therefore expected
            Assert.assertTrue(throwable.getMessage().startsWith("Referenced security token could not be retrieved (Reference "));
        }
    }

    /*
    Todo correct this test.
    @Test
    public void testRecursiveKeyReferencesDOS2() throws Exception {
        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

        String action = WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPT;
        Properties properties = new Properties();
        properties.setProperty(WSHandlerConstants.SIGNATURE_PARTS, "{Element}{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp;{Element}{http://schemas.xmlsoap.org/soap/envelope/}Body;");
        Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

        XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey");
        Element encryptedKeyElement = (Element) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
        encryptedKeyElement.removeAttribute("Id");
        encryptedKeyElement.setAttribute("Id", "2");

        xPathExpression = getXPath(".//dsig:X509Data");
        Element keyIdentifierElement = (Element) xPathExpression.evaluate(encryptedKeyElement, XPathConstants.NODE);
        Element securityTokenReferenceElement = (Element) keyIdentifierElement.getParentNode();
        securityTokenReferenceElement.removeChild(keyIdentifierElement);
        //wsse:Reference xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" URI="#EncKeyId-1483925398"/>
        Element referenceElement = securedDocument.createElementNS(Constants.TAG_wsse_Reference.getNamespaceURI(), Constants.TAG_wsse_Reference.getLocalPart());
        referenceElement.setAttribute("URI", "#1");
        securityTokenReferenceElement.appendChild(referenceElement);

        Element clonedEncryptedElement = (Element) encryptedKeyElement.cloneNode(true);
        clonedEncryptedElement.removeAttribute("Id");
        clonedEncryptedElement.setAttribute("Id", "1");

        xPathExpression = getXPath(".//wsse:Reference");
        Element newReferenceElement = (Element) xPathExpression.evaluate(clonedEncryptedElement, XPathConstants.NODE);
        newReferenceElement.removeAttribute("URI");
        newReferenceElement.setAttribute("URI", "#2");

        Element securityHeaderNode = (Element) encryptedKeyElement.getParentNode();
        securityHeaderNode.insertBefore(clonedEncryptedElement, encryptedKeyElement);

        doInboundSecurityWithWSS4J(securedDocument, WSHandlerConstants.ENCRYPT);
    }
    */

    /**
     * Tests what happens when an soapAction from an other operation is provided.
     * Can the policy framework be bypassed?
     */
    @Test
    public void testSOAPActionSpoofing() throws Exception {
        SecurityProperties outSecurityProperties = new SecurityProperties();
        outSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        outSecurityProperties.setEncryptionUser("receiver");
        outSecurityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outSecurityProperties.setSignatureUser("transmitter");
        outSecurityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());

        outSecurityProperties.addSignaturePart(new SecurePart(Constants.TAG_wsu_Timestamp.getLocalPart(), Constants.TAG_wsu_Timestamp.getNamespaceURI(), "Element"));
        outSecurityProperties.addSignaturePart(new SecurePart(Constants.TAG_soap_Body_LocalName, Constants.NS_SOAP11, "Element"));
        outSecurityProperties.addEncryptionPart(new SecurePart(Constants.TAG_soap_Body_LocalName, Constants.NS_SOAP11, "Element"));
        Constants.Action[] actions = new Constants.Action[]{Constants.Action.TIMESTAMP, Constants.Action.SIGNATURE, Constants.Action.ENCRYPT};
        outSecurityProperties.setOutAction(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);


        SecurityProperties inSecurityProperties = new SecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        PolicyEnforcerFactory policyEnforcerFactory = PolicyEnforcerFactory.newInstance(this.getClass().getClassLoader().getResource("testdata/wsdl/actionSpoofing.wsdl"));
        PolicyEnforcer policyEnforcer = policyEnforcerFactory.newPolicyEnforcer("emptyPolicy");
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, null));

        try {
            Document document = doInboundSecurity(inSecurityProperties, new ByteArrayInputStream(baos.toByteArray()), policyEnforcer);
            Assert.fail("Expected XMLStreamException");
        } catch (XMLStreamException e) {
            Throwable throwable = e.getCause();
            Assert.assertNotNull(throwable);
            Assert.assertTrue(throwable instanceof WSSecurityException);
            Assert.assertEquals(throwable.getMessage(), "SOAPAction does not match with the current Operation");
        }
    }

    @Test
    public void testSignedBodyRelocationToHeader() throws Exception {
        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

        String action = WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPT;
        Properties properties = new Properties();
        properties.setProperty(WSHandlerConstants.SIGNATURE_PARTS, "{Element}{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp;{Element}{http://schemas.xmlsoap.org/soap/envelope/}Body;");
        properties.setProperty(WSHandlerConstants.ENC_SYM_ALGO, "http://www.w3.org/2001/04/xmlenc#aes256-cbc");
        Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

        XPathExpression xPathExpression = getXPath("/env:Envelope/env:Body");
        Element bodyElement = (Element) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
        Element soapEnvElement = (Element) bodyElement.getParentNode();
        soapEnvElement.removeChild(bodyElement);

        Element newBody = securedDocument.createElementNS(Constants.NS_SOAP11, Constants.TAG_soap_Body_LocalName);
        soapEnvElement.appendChild(newBody);

        xPathExpression = getXPath("/env:Envelope/env:Header");
        Element headerElement = (Element) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
        headerElement.appendChild(bodyElement);

        SecurityProperties inSecurityProperties = new SecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        PolicyEnforcerFactory policyEnforcerFactory = PolicyEnforcerFactory.newInstance(this.getClass().getClassLoader().getResource("testdata/wsdl/actionSpoofing.wsdl"));
        PolicyEnforcer policyEnforcer = policyEnforcerFactory.newPolicyEnforcer("goodPolicy");
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, null));

        try {
            Document document = doInboundSecurity(inSecurityProperties, new CustomW3CDOMStreamReader(securedDocument), policyEnforcer);
            Assert.fail("Expected XMLStreamException");
        } catch (XMLStreamException e) {
            Throwable throwable = e.getCause();
            Assert.assertNotNull(throwable);
            Assert.assertTrue(throwable instanceof WSSPolicyException);
            Assert.assertEquals(throwable.getMessage(), "No policy alternative could be satisfied");
        }
    }

    /**
     * Since we don't support (yet) external URI refs this shouldn't be a problem.
     * <p/>
     * todo this test modifies signed content. test with encryption uri's or so
     *
     * @throws Exception
     */
    @Test
    public void test_publicURIReferenceDOS() throws Exception {
        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

        String action = WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPT;
        Properties properties = new Properties();
        properties.setProperty(WSHandlerConstants.SIGNATURE_PARTS, "{Element}{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp;{Element}{http://schemas.xmlsoap.org/soap/envelope/}Body;");
        properties.setProperty(WSHandlerConstants.ENC_SYM_ALGO, "http://www.w3.org/2001/04/xmlenc#aes256-cbc");
        Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

        XPathExpression xPathExpression = getXPath("//@URI");
        Attr uri = (Attr) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
        uri.setNodeValue("http://www.kernel.org/pub/linux/kernel/v2.6/linux-2.6.23.tar.gz");

        //doInboundSecurityWithWSS4J(securedDocument, WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPT);

        SecurityProperties inSecurityProperties = new SecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        try {
            Document document = doInboundSecurity(inSecurityProperties, new CustomW3CDOMStreamReader(securedDocument));
            Assert.fail("Expected XMLStreamException");
        } catch (XMLStreamException e) {
            Throwable throwable = e.getCause();
            Assert.assertNotNull(throwable);
            Assert.assertTrue(throwable instanceof WSSecurityException);
            Assert.assertEquals(throwable.getMessage(), "The signature or decryption was invalid (Digest verification failed)");
        }
    }

    @Test
    public void testTransformationCodeInjection() throws Exception {
        //todo when stream-xml-sec signature supports transformations
        //probably we never will. This is a big security hole!
    }

    /*
    ** This test cannot be done here. We rely on the correct settings of the
    * XMLStreamReader which is taken over us. @see InboundWSSec#processInMessage

    @Test
    public void test_DosAttackWithRecursiveEntity() throws Exception {
        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

        String action = WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPT;
        Properties properties = new Properties();
        properties.setProperty(WSHandlerConstants.SIGNATURE_PARTS, "{Element}{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp;{Element}{http://schemas.xmlsoap.org/soap/envelope/}Body;");
        properties.setProperty(WSHandlerConstants.ENC_SYM_ALGO, "http://www.w3.org/2001/04/xmlenc#aes256-cbc");
        Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

        XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header");
        Element headerElement = (Element) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
        Element newElement = securedDocument.createElement("test");
        headerElement.appendChild(newElement);
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        InputStream dtd = this.getClass().getClassLoader().getResourceAsStream("testdata/recursiveDTD.txt");
        byte[] buff = new byte[1024];
        int read = 0;
        while ((read = dtd.read(buff)) != -1) {
            baos.write(buff, 0, read);
        }
        dtd.close();

        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));

        String soap = new String(baos.toByteArray(), "utf-8");
        soap = soap.replaceFirst("<test/>", "<test>&x100;</test>");

        System.out.println(soap);

        SecurityProperties inSecurityProperties = new SecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());

        try {
            Document document = doInboundSecurity(inSecurityProperties, new ByteArrayInputStream(soap.getBytes()));
            Assert.fail("Expected XMLStreamException");
        } catch (XMLStreamException e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
            Throwable throwable = e.getCause();
            Assert.assertNotNull(throwable);
            Assert.assertTrue(throwable instanceof WSSecurityException);
            throwable = throwable.getCause();
            Assert.assertNotNull(throwable);
            Assert.assertTrue(throwable instanceof PolicyViolationException);
            throwable = throwable.getCause();
            Assert.assertNotNull(throwable);
            Assert.assertTrue(throwable instanceof PolicyViolationException);
            Assert.assertEquals(throwable.getMessage(), "No policy alternative could be satisfied");
        }
    }
    */
}
