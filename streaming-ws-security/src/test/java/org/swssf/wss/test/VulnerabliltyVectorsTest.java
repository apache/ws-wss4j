/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.swssf.wss.test;

import org.apache.ws.security.handler.WSHandlerConstants;
import org.swssf.wss.WSSec;
import org.swssf.wss.ext.InboundWSSec;
import org.swssf.wss.ext.WSSConstants;
import org.swssf.wss.ext.WSSSecurityProperties;
import org.swssf.wss.ext.WSSecurityException;
import org.swssf.wss.test.utils.StAX2DOM;
import org.apache.xml.security.stax.ext.XMLSecurityException;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Properties;

/**
 * @author $Author$
 * @version $Revision$ $Date$
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
        Element referenceElement = securedDocument.createElementNS(WSSConstants.TAG_wsse_Reference.getNamespaceURI(), WSSConstants.TAG_wsse_Reference.getLocalPart());
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

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
        transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));

        WSSSecurityProperties securityProperties = new WSSSecurityProperties();
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());
        securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        //we have to disable the schema validation until WSS4J-DOM is fixed. WSS4J generates an empty PrefixList which is not schema valid!
        securityProperties.setDisableSchemaValidation(true);

        try {
            doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));
            Assert.fail("Expected XMLStreamException");
        } catch (XMLStreamException e) {
            Throwable throwable = e.getCause();
            Assert.assertNotNull(throwable);
            Assert.assertTrue(throwable instanceof XMLSecurityException);
            //we expect a "No SecurityToken found" since WSS says that a token must be declared before use.
            //the declare before use is in the nature of streaming xml-security and therefore expected
            //Assert.assertEquals(throwable.getMessage(), "An invalid security token was provided");
            Assert.assertEquals(throwable.getMessage(), "An invalid security token was provided");
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
        Element referenceElement = securedDocument.createElementNS(WSSConstants.TAG_wsse_Reference.getNamespaceURI(), WSSConstants.TAG_wsse_Reference.getLocalPart());
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
     * Since we don't support (yet) external URI refs this shouldn't be a problem.
     * <p/>
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

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
        transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));

        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.addIgnoreBSPRule(WSSConstants.BSPRule.R3006);
        //we have to disable the schema validation until WSS4J-DOM is fixed. WSS4J generates an empty PrefixList which is not schema valid!
        inSecurityProperties.setDisableSchemaValidation(true);

        try {
            doInboundSecurity(inSecurityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));
            Assert.fail("Expected XMLStreamException");
        } catch (XMLStreamException e) {
            Throwable throwable = e.getCause();
            Assert.assertNotNull(throwable);
            //todo exception should be a WSSecurityException
            Assert.assertTrue(throwable instanceof XMLSecurityException);
            Assert.assertTrue(throwable.getMessage().contains("The signature or decryption was invalid (Digest verification failed for URI"));
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

        WSSSecurityProperties inSecurityProperties = new WSSSecurityProperties();
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

    @Test
    public void testReplayAttackInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.SIGNATURE_PARTS, "{Element}{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp;{Element}{http://schemas.xmlsoap.org/soap/envelope/}Body;");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done signature; now test sig-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            //we have to disable the schema validation until WSS4J-DOM is fixed. WSS4J generates an empty PrefixList which is not schema valid!
            securityProperties.setDisableSchemaValidation(true);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            try {
                xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));
                StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                Assert.fail("Expected XMLStreamException");
            } catch (XMLStreamException e) {
                Assert.assertEquals(e.getMessage(), "org.swssf.wss.ext.WSSecurityException: The message has expired");
            }
        }
    }
}
