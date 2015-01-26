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
package org.apache.wss4j.stax.test;

import org.apache.commons.compress.compressors.xz.XZCompressorInputStream;
import org.apache.commons.compress.compressors.xz.XZCompressorOutputStream;
import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.stax.WSSec;
import org.apache.wss4j.stax.ext.InboundWSSec;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.test.utils.StAX2DOM;
import org.apache.xml.security.stax.config.Init;
import org.apache.xml.security.stax.config.TransformerAlgorithmMapper;
import org.junit.Assert;
import org.junit.Test;
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

import java.io.*;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;

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

        XPathExpression xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey");
        Element encryptedKeyElement = (Element) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
        encryptedKeyElement.removeAttribute("Id");
        encryptedKeyElement.setAttributeNS(null, "Id", "G2");

        xPathExpression = getXPath(".//dsig:X509Data");
        Element keyIdentifierElement = (Element) xPathExpression.evaluate(encryptedKeyElement, XPathConstants.NODE);
        Element securityTokenReferenceElement = (Element) keyIdentifierElement.getParentNode();
        securityTokenReferenceElement.removeChild(keyIdentifierElement);
        //wsse:Reference xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" URI="#EncKeyId-1483925398"/>
        Element referenceElement = securedDocument.createElementNS(WSSConstants.TAG_wsse_Reference.getNamespaceURI(), WSSConstants.TAG_wsse_Reference.getLocalPart());
        referenceElement.setAttributeNS(null, "URI", "#G1");
        securityTokenReferenceElement.appendChild(referenceElement);

        Element clonedEncryptedElement = (Element) encryptedKeyElement.cloneNode(true);
        clonedEncryptedElement.removeAttribute("Id");
        clonedEncryptedElement.setAttributeNS(null, "Id", "G1");

        xPathExpression = getXPath(".//wsse:Reference");
        Element newReferenceElement = (Element) xPathExpression.evaluate(clonedEncryptedElement, XPathConstants.NODE);
        newReferenceElement.removeAttribute("URI");
        newReferenceElement.setAttributeNS(null, "URI", "#G2");

        Element securityHeaderNode = (Element) encryptedKeyElement.getParentNode();
        securityHeaderNode.insertBefore(clonedEncryptedElement, encryptedKeyElement);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
        transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));

        WSSSecurityProperties securityProperties = new WSSSecurityProperties();
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());
        securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        try {
            doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));
            Assert.fail("Expected XMLStreamException");
        } catch (XMLStreamException e) {
            Throwable throwable = e.getCause();
            Assert.assertNotNull(throwable);
            //we expect a "No SecurityToken found" since WSS says that a token must be declared before use.
            //the declare before use is in the nature of streaming xml-security and therefore expected
            //Assert.assertEquals(throwable.getMessage(), "An invalid security token was provided");
            Assert.assertEquals(throwable.getMessage(), "Recursive key reference detected.");
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

        XPathExpression xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey");
        Element encryptedKeyElement = (Element) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
        encryptedKeyElement.removeAttribute("Id");
        encryptedKeyElement.setAttributeNS(null, "Id", "2");

        xPathExpression = getXPath(".//dsig:X509Data");
        Element keyIdentifierElement = (Element) xPathExpression.evaluate(encryptedKeyElement, XPathConstants.NODE);
        Element securityTokenReferenceElement = (Element) keyIdentifierElement.getParentNode();
        securityTokenReferenceElement.removeChild(keyIdentifierElement);
        //wsse:Reference xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" URI="#EncKeyId-1483925398"/>
        Element referenceElement = securedDocument.createElementNS(WSSConstants.TAG_wsse_Reference.getNamespaceURI(), WSSConstants.TAG_wsse_Reference.getLocalPart());
        referenceElement.setAttributeNS(null, "URI", "#1");
        securityTokenReferenceElement.appendChild(referenceElement);

        Element clonedEncryptedElement = (Element) encryptedKeyElement.cloneNode(true);
        clonedEncryptedElement.removeAttribute("Id");
        clonedEncryptedElement.setAttributeNS(null, "Id", "1");

        xPathExpression = getXPath(".//wsse:Reference");
        Element newReferenceElement = (Element) xPathExpression.evaluate(clonedEncryptedElement, XPathConstants.NODE);
        newReferenceElement.removeAttribute("URI");
        newReferenceElement.setAttributeNS(null, "URI", "#2");

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
        inSecurityProperties.addIgnoreBSPRule(BSPRule.R3006);

        try {
            doInboundSecurity(inSecurityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));
            Assert.fail("Expected XMLStreamException");
        } catch (XMLStreamException e) {
            Throwable throwable = e.getCause();
            Assert.assertNotNull(throwable);
            Assert.assertTrue(throwable.getMessage().contains("Invalid digest of reference "));
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

        XPathExpression xPathExpression = getXPath("/soap:Envelope/soap:Header");
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
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties, false, true);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            try {
                xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));
                StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                Assert.fail("Expected XMLStreamException");
            } catch (XMLStreamException e) {
                Assert.assertEquals(((WSSecurityException) e.getCause()).getFaultCode(), WSSecurityException.MESSAGE_EXPIRED);
            }
        }
    }

    @Test
    public void testMaximumAllowedReferencesPerManifest() throws Exception {

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

        String action = WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPT;
        Properties properties = new Properties();
        properties.setProperty(WSHandlerConstants.SIGNATURE_PARTS, "{Element}{http://www.w3.org/1999/XMLSchema}complexType;{Element}{http://www.w3.org/1999/XMLSchema}simpleType;");
        Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
        transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));

        WSSSecurityProperties securityProperties = new WSSSecurityProperties();
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());
        securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        try {
            doInboundSecurity(securityProperties,
                    xmlInputFactory.createXMLStreamReader(
                            new ByteArrayInputStream(baos.toByteArray())));
            Assert.fail("Expected XMLStreamException");
        } catch (XMLStreamException e) {
            Assert.assertTrue(e.getCause() instanceof WSSecurityException);
            Assert.assertEquals(((WSSecurityException) e.getCause()).getFaultCode(), WSSecurityException.INVALID_SECURITY);
        }
    }

    @Test
    public void testMaximumAllowedTransformsPerReference() throws Exception {
        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

        String action = WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPT;
        Properties properties = new Properties();
        properties.setProperty(WSHandlerConstants.SIGNATURE_PARTS, "{Element}{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp;{Element}{http://schemas.xmlsoap.org/soap/envelope/}Body;");
        Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
        transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));

        WSSSecurityProperties securityProperties = new WSSSecurityProperties();
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());
        securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        int oldval = 0;
        try {
            Init.init(WSSec.class.getClassLoader().getResource("wss/wss-config.xml").toURI(), WSSec.class);
            oldval = changeValueOfMaximumAllowedTransformsPerReference(0);
            doInboundSecurity(securityProperties,
                    xmlInputFactory.createXMLStreamReader(
                            new ByteArrayInputStream(baos.toByteArray())));
            Assert.fail("Expected XMLStreamException");
        } catch (XMLStreamException e) {
            Assert.assertTrue(e.getCause() instanceof WSSecurityException);
            Assert.assertEquals(((WSSecurityException) e.getCause()).getFaultCode(), WSSecurityException.INVALID_SECURITY);
        } finally {
            changeValueOfMaximumAllowedTransformsPerReference(oldval);
        }
    }


    @Test
    public void testDisallowMD5Algorithm() throws Exception {
        WSSSecurityProperties outboundSecurityProperties = new WSSSecurityProperties();
        outboundSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        outboundSecurityProperties.setEncryptionUser("receiver");
        outboundSecurityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outboundSecurityProperties.setSignatureUser("transmitter");
        outboundSecurityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outboundSecurityProperties.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-md5");
        List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
        actions.add(WSSConstants.TIMESTAMP);
        actions.add(WSSConstants.SIGNATURE);
        actions.add(WSSConstants.ENCRYPT);
        outboundSecurityProperties.setActions(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outboundSecurityProperties, sourceDocument);

        WSSSecurityProperties inboundsecurityProperties = new WSSSecurityProperties();
        inboundsecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inboundsecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inboundsecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inboundsecurityProperties.addIgnoreBSPRule(BSPRule.R5421);

        try {
            doInboundSecurity(inboundsecurityProperties,
                    xmlInputFactory.createXMLStreamReader(
                            new ByteArrayInputStream(baos.toByteArray())));
            Assert.fail("Expected XMLStreamException");
        } catch (XMLStreamException e) {
            Assert.assertTrue(e.getCause() instanceof WSSecurityException);
            Assert.assertEquals(((WSSecurityException) e.getCause()).getFaultCode(), WSSecurityException.FAILED_CHECK);
        }
    }


    @Test
    public void testAllowMD5Algorithm() throws Exception {

        if (getJavaSpecificationVersion() >= 1.7) {
            System.out.println("testAllowMD5Algorithm skipped");
            return;
        }

        WSSSecurityProperties outboundSecurityProperties = new WSSSecurityProperties();
        outboundSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        outboundSecurityProperties.setEncryptionUser("receiver");
        outboundSecurityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outboundSecurityProperties.setSignatureUser("transmitter");
        outboundSecurityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outboundSecurityProperties.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-md5");
        List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
        actions.add(WSSConstants.TIMESTAMP);
        actions.add(WSSConstants.SIGNATURE);
        actions.add(WSSConstants.ENCRYPT);
        outboundSecurityProperties.setActions(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outboundSecurityProperties, sourceDocument);

        WSSSecurityProperties inboundsecurityProperties = new WSSSecurityProperties();
        inboundsecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inboundsecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inboundsecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inboundsecurityProperties.addIgnoreBSPRule(BSPRule.R5421);

        try {
            Init.init(WSSec.class.getClassLoader().getResource("wss/wss-config.xml").toURI(), WSSec.class);
            switchAllowMD5Algorithm(true);
            Document document = doInboundSecurity(inboundsecurityProperties,
                    xmlInputFactory.createXMLStreamReader(
                            new ByteArrayInputStream(baos.toByteArray())));
            Assert.assertNotNull(document);
        } finally {
            switchAllowMD5Algorithm(false);
        }
    }

    @Test
    public void testMaximumAllowedXMLStructureDepth() throws Exception {

        if (getJavaSpecificationVersion() >= 1.7) {
            System.out.println("testAllowMD5Algorithm skipped");
            return;
        }

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

        String action = WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE;
        Properties properties = new Properties();
        properties.setProperty(WSHandlerConstants.SIGNATURE_PARTS, "{Element}{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp;{Element}{http://schemas.xmlsoap.org/soap/envelope/}Body;");
        Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
        transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));

        WSSSecurityProperties securityProperties = new WSSSecurityProperties();
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());
        securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        int oldval = 0;
        try {
            Init.init(WSSec.class.getClassLoader().getResource("wss/wss-config.xml").toURI(), WSSec.class);
            oldval = changeValueOfMaximumAllowedXMLStructureDepth(10);
            doInboundSecurity(securityProperties,
                    xmlInputFactory.createXMLStreamReader(
                            new ByteArrayInputStream(baos.toByteArray())));
            Assert.fail("Expected XMLStreamException");
        } catch (XMLStreamException e) {
            Assert.assertEquals(e.getCause().getMessage(),
                    "Maximum depth (10) of the XML structure reached. You can raise the maximum via the " +
                    "\"MaximumAllowedXMLStructureDepth\" property in the configuration.");
        } finally {
            changeValueOfMaximumAllowedXMLStructureDepth(oldval);
        }
    }

    @Test
    public void testMaximumAllowedXMLStructureDepthInEncryptedContent() throws Exception {

        if (getJavaSpecificationVersion() >= 1.7) {
            System.out.println("testAllowMD5Algorithm skipped");
            return;
        }

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

        String action = WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPT;
        Properties properties = new Properties();
        properties.setProperty(WSHandlerConstants.SIGNATURE_PARTS, "{Element}{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp;{Element}{http://schemas.xmlsoap.org/soap/envelope/}Body;");
        Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
        transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));

        WSSSecurityProperties securityProperties = new WSSSecurityProperties();
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());
        securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        int oldval = 0;
        try {
            Init.init(WSSec.class.getClassLoader().getResource("wss/wss-config.xml").toURI(), WSSec.class);
            oldval = changeValueOfMaximumAllowedXMLStructureDepth(10);
            doInboundSecurity(securityProperties,
                    xmlInputFactory.createXMLStreamReader(
                            new ByteArrayInputStream(baos.toByteArray())));
            Assert.fail("Expected XMLStreamException");
        } catch (XMLStreamException e) {
            Assert.assertEquals(e.getCause().getMessage(),
                    "Maximum depth (10) of the XML structure reached. You can raise the maximum via the " +
                    "\"MaximumAllowedXMLStructureDepth\" property in the configuration.");
            Assert.assertEquals(((WSSecurityException) e.getCause()).getFaultCode(), WSSecurityException.FAILED_CHECK);
        } finally {
            changeValueOfMaximumAllowedXMLStructureDepth(oldval);
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testMaximumAllowedDecompressedBytes() throws Exception {

        long oldval = 0;
        try {
            Init.init(WSSec.class.getClassLoader().getResource("wss/wss-config.xml").toURI(), WSSec.class);
            Field algorithmsClassMapField = TransformerAlgorithmMapper.class.getDeclaredField("algorithmsClassMapOut");
            algorithmsClassMapField.setAccessible(true);
            Map<String, Class<?>> map = (Map<String, Class<?>>)algorithmsClassMapField.get(null);
            map.put("http://www.apache.org/2012/04/xmlsec/xz", XZCompressorOutputStream.class);
            algorithmsClassMapField = TransformerAlgorithmMapper.class.getDeclaredField("algorithmsClassMapIn");
            algorithmsClassMapField.setAccessible(true);
            map = (Map<String, Class<?>>)algorithmsClassMapField.get(null);
            map.put("http://www.apache.org/2012/04/xmlsec/xz", XZCompressorInputStream.class);
            oldval = changeValueOfMaximumAllowedDecompressedBytes(101L);

            WSSSecurityProperties outboundSecurityProperties = new WSSSecurityProperties();
            outboundSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
            outboundSecurityProperties.setEncryptionUser("receiver");
            outboundSecurityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            outboundSecurityProperties.setSignatureUser("transmitter");
            outboundSecurityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
            actions.add(WSSConstants.TIMESTAMP);
            actions.add(WSSConstants.SIGNATURE);
            actions.add(WSSConstants.ENCRYPT);
            outboundSecurityProperties.setActions(actions);
            outboundSecurityProperties.setEncryptionCompressionAlgorithm("http://www.apache.org/2012/04/xmlsec/xz");

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            ByteArrayOutputStream baos = doOutboundSecurity(outboundSecurityProperties, sourceDocument);


            WSSSecurityProperties inboundSecurityProperties = new WSSSecurityProperties();
            inboundSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
            inboundSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            inboundSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

            doInboundSecurity(inboundSecurityProperties,
                    xmlInputFactory.createXMLStreamReader(
                            new ByteArrayInputStream(baos.toByteArray())));
            Assert.fail("Expected XMLStreamException");
        } catch (XMLStreamException e) {
            Assert.assertTrue(e.getCause() instanceof IOException);
            Assert.assertEquals(e.getCause().getMessage(),
                    "Maximum byte count (101) reached.");
        } finally {
            changeValueOfMaximumAllowedDecompressedBytes(oldval);
        }
    }

    @Test
    public void testModifiedEncryptedKeyCipherValue() throws Exception {

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

        String action = WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPT;
        Properties properties = new Properties();
        properties.setProperty(WSHandlerConstants.SIGNATURE_PARTS, "{Element}{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp;{Element}{http://schemas.xmlsoap.org/soap/envelope/}Body;");
        Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        NodeList cipherValues = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_xenc_CipherValue.getNamespaceURI(), WSSConstants.TAG_xenc_CipherValue.getLocalPart());
        Element cipherValueElement = (Element)cipherValues.item(0);
        Assert.assertEquals(cipherValueElement.getParentNode().getParentNode().getLocalName(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());

        String cipherValue = cipherValueElement.getTextContent();
        StringBuilder stringBuilder = new StringBuilder(cipherValue);
        int index = stringBuilder.length() / 2;
        char ch = stringBuilder.charAt(index);
        if (ch != 'A') {
            ch = 'A';
        } else {
            ch = 'B';
        }
        stringBuilder.setCharAt(index, ch);
        cipherValueElement.setTextContent(stringBuilder.toString());

        javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
        transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));

        WSSSecurityProperties inboundsecurityProperties = new WSSSecurityProperties();
        inboundsecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inboundsecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inboundsecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        try {
            doInboundSecurity(inboundsecurityProperties,
                    xmlInputFactory.createXMLStreamReader(
                            new ByteArrayInputStream(baos.toByteArray())));
            Assert.fail("Expected XMLStreamException");
        } catch (XMLStreamException e) {
            Assert.assertFalse(e.getMessage().contains("data hash wrong"));
        }
    }

    /**
     * Test if the RSA 1.5 key transport algorithm will be rejected by default.
     * Standard key transport algorithm is RSA-OAEP
     */
    @Test
    public void testDisallowRSA15Algorithm() throws Exception {
        WSSSecurityProperties outboundSecurityProperties = new WSSSecurityProperties();
        outboundSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        outboundSecurityProperties.setEncryptionUser("receiver");
        outboundSecurityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outboundSecurityProperties.setSignatureUser("transmitter");
        outboundSecurityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outboundSecurityProperties.setEncryptionKeyTransportAlgorithm("http://www.w3.org/2001/04/xmlenc#rsa-1_5");
        List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
        actions.add(WSSConstants.TIMESTAMP);
        actions.add(WSSConstants.SIGNATURE);
        actions.add(WSSConstants.ENCRYPT);
        outboundSecurityProperties.setActions(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outboundSecurityProperties, sourceDocument);

        WSSSecurityProperties inboundsecurityProperties = new WSSSecurityProperties();
        inboundsecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inboundsecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inboundsecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inboundsecurityProperties.addIgnoreBSPRule(BSPRule.R5421);

        try {
            doInboundSecurity(inboundsecurityProperties,
                    xmlInputFactory.createXMLStreamReader(
                            new ByteArrayInputStream(baos.toByteArray())));
            Assert.fail("Expected XMLStreamException");
        } catch (XMLStreamException e) {
            Assert.assertTrue(e.getCause() instanceof WSSecurityException);
            Assert.assertEquals(((WSSecurityException) e.getCause()).getFaultCode(), WSSecurityException.FAILED_CHECK);
        }
    }
}
