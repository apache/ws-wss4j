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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;

import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorOutputStream;
import org.apache.wss4j.common.ConfigurationConstants;
import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.KeyUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.dom.message.WSSecEncrypt;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.securityEvent.EncryptedPartSecurityEvent;
import org.apache.wss4j.stax.securityEvent.OperationSecurityEvent;
import org.apache.wss4j.stax.securityEvent.WSSecurityEventConstants;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.wss4j.stax.setup.ConfigurationConverter;
import org.apache.wss4j.stax.setup.InboundWSSec;
import org.apache.wss4j.stax.setup.OutboundWSSec;
import org.apache.wss4j.stax.setup.WSSec;
import org.apache.wss4j.stax.test.utils.StAX2DOM;
import org.apache.wss4j.stax.test.utils.XmlReaderToWriter;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.config.Init;
import org.apache.xml.security.stax.config.TransformerAlgorithmMapper;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.securityEvent.ContentEncryptedElementSecurityEvent;
import org.apache.xml.security.stax.securityEvent.EncryptedElementSecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEventConstants;
import org.apache.xml.security.utils.XMLUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

public class EncDecryptionTest extends AbstractTestBase {

    private boolean isIBMJdK = System.getProperty("java.vendor").contains("IBM");

    @Test
    public void testEncDecryptionDefaultConfigurationOutbound() throws Exception {

        ByteArrayOutputStream baos;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.ENCRYPTION);
            securityProperties.setActions(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            XPathExpression xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p']");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_DataReference.getNamespaceURI(), WSSConstants.TAG_xenc_DataReference.getLocalPart());
            assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 1);

            xPathExpression = getXPath("/soap:Envelope/soap:Body/xenc:EncryptedData/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2001/04/xmlenc#aes256-cbc']");
            node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            assertNotNull(node);

            assertEquals(node.getParentNode().getParentNode().getLocalName(), "Body");
            NodeList childNodes = node.getParentNode().getParentNode().getChildNodes();
            for (int i = 0; i < childNodes.getLength(); i++) {
                Node child = childNodes.item(i);
                if (child.getNodeType() == Node.TEXT_NODE) {
                    assertEquals(child.getTextContent().trim(), "");
                } else if (child.getNodeType() == Node.ELEMENT_NODE) {
                    assertEquals(child, nodeList.item(0));
                } else {
                    fail("Unexpected Node encountered");
                }
            }
        }

        //done encryption; now test decryption:
        {
            String action = WSHandlerConstants.ENCRYPTION;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testEncDecryptionDefaultConfigurationInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.ENCRYPTION;
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, new Properties());

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p']");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            assertNotNull(node);

            Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }
        //test streaming decryption
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            WSSecurityEventConstants.Event[] expectedSecurityEvents = new WSSecurityEventConstants.Event[]{
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.X509Token,
                    WSSecurityEventConstants.ENCRYPTED_PART,
                    WSSecurityEventConstants.OPERATION,
            };
            final TestSecurityEventListener securityEventListener = new TestSecurityEventListener(expectedSecurityEvents);

            Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), securityEventListener);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 0);

            securityEventListener.compare();

            List<SecurityEvent> receivedSecurityEvents = securityEventListener.getReceivedSecurityEvents();
            for (int i = 0; i < receivedSecurityEvents.size(); i++) {
                SecurityEvent securityEvent = receivedSecurityEvents.get(i);
                if (securityEvent.getSecurityEventType() == WSSecurityEventConstants.OPERATION) {
                    OperationSecurityEvent operationSecurityEvent = (OperationSecurityEvent) securityEvent;
                    assertEquals(operationSecurityEvent.getOperation(), new QName("http://schemas.xmlsoap.org/wsdl/", "definitions"));
                } else if (securityEvent.getSecurityEventType() == WSSecurityEventConstants.ENCRYPTED_PART) {
                    EncryptedPartSecurityEvent encryptedPartSecurityEvent = (EncryptedPartSecurityEvent) securityEvent;
                    assertNotNull(encryptedPartSecurityEvent.getXmlSecEvent());
                    assertNotNull(encryptedPartSecurityEvent.getSecurityToken());
                    assertNotNull(encryptedPartSecurityEvent.getElementPath());
                    final QName expectedElementName = new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body");
                    assertEquals(encryptedPartSecurityEvent.getXmlSecEvent().asStartElement().getName(), expectedElementName);
                    assertEquals(encryptedPartSecurityEvent.getElementPath().size(), 2);
                    assertEquals(encryptedPartSecurityEvent.getElementPath().get(encryptedPartSecurityEvent.getElementPath().size() - 1), expectedElementName);
                }
            }

            EncryptedPartSecurityEvent encryptedPartSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.ENCRYPTED_PART);
            OperationSecurityEvent operationSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.OPERATION);
            String encryptedPartCorrelationID = encryptedPartSecurityEvent.getCorrelationID();
            String operationCorrelationID = operationSecurityEvent.getCorrelationID();

            List<SecurityEvent> operationSecurityEvents = new ArrayList<>();
            List<SecurityEvent> encryptedPartSecurityEvents = new ArrayList<>();

            List<SecurityEvent> securityEvents = securityEventListener.getReceivedSecurityEvents();
            for (int i = 0; i < securityEvents.size(); i++) {
                SecurityEvent securityEvent = securityEvents.get(i);
                if (securityEvent.getCorrelationID().equals(encryptedPartCorrelationID)) {
                    encryptedPartSecurityEvents.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(operationCorrelationID)) {
                    operationSecurityEvents.add(securityEvent);
                }
            }

            assertEquals(4, encryptedPartSecurityEvents.size());
            assertEquals(securityEventListener.getReceivedSecurityEvents().size(),
                    operationSecurityEvents.size() + encryptedPartSecurityEvents.size());
        }
    }

    @Test
    public void testEncDecryptionCryptoPropertiesOutbound() throws Exception {

        ByteArrayOutputStream baos;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.ENCRYPTION);
            securityProperties.setActions(actions);
            Properties properties =
                CryptoFactory.getProperties("transmitter-crypto.properties", this.getClass().getClassLoader());
            securityProperties.setEncryptionCryptoProperties(properties);
            securityProperties.setEncryptionUser("receiver");

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            XPathExpression xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p']");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_DataReference.getNamespaceURI(), WSSConstants.TAG_xenc_DataReference.getLocalPart());
            assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 1);

            xPathExpression = getXPath("/soap:Envelope/soap:Body/xenc:EncryptedData/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2001/04/xmlenc#aes256-cbc']");
            node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            assertNotNull(node);

            assertEquals(node.getParentNode().getParentNode().getLocalName(), "Body");
            NodeList childNodes = node.getParentNode().getParentNode().getChildNodes();
            for (int i = 0; i < childNodes.getLength(); i++) {
                Node child = childNodes.item(i);
                if (child.getNodeType() == Node.TEXT_NODE) {
                    assertEquals(child.getTextContent().trim(), "");
                } else if (child.getNodeType() == Node.ELEMENT_NODE) {
                    assertEquals(child, nodeList.item(0));
                } else {
                    fail("Unexpected Node encountered");
                }
            }
        }

        //done encryption; now test decryption:
        {
            String action = WSHandlerConstants.ENCRYPTION;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testEncDecryptionCryptoPropertiesInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.ENCRYPTION;
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, new Properties());

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p']");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            assertNotNull(node);

            Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }
        //test streaming decryption
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            Properties properties =
                CryptoFactory.getProperties("receiver-crypto.properties", this.getClass().getClassLoader());
            securityProperties.setDecryptionCryptoProperties(properties);
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            WSSecurityEventConstants.Event[] expectedSecurityEvents = new WSSecurityEventConstants.Event[]{
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.X509Token,
                    WSSecurityEventConstants.ENCRYPTED_PART,
                    WSSecurityEventConstants.OPERATION,
            };
            final TestSecurityEventListener securityEventListener = new TestSecurityEventListener(expectedSecurityEvents);

            Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), securityEventListener);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 0);

            securityEventListener.compare();

            List<SecurityEvent> receivedSecurityEvents = securityEventListener.getReceivedSecurityEvents();
            for (int i = 0; i < receivedSecurityEvents.size(); i++) {
                SecurityEvent securityEvent = receivedSecurityEvents.get(i);
                if (securityEvent.getSecurityEventType() == WSSecurityEventConstants.OPERATION) {
                    OperationSecurityEvent operationSecurityEvent = (OperationSecurityEvent) securityEvent;
                    assertEquals(operationSecurityEvent.getOperation(), new QName("http://schemas.xmlsoap.org/wsdl/", "definitions"));
                } else if (securityEvent.getSecurityEventType() == WSSecurityEventConstants.ENCRYPTED_PART) {
                    EncryptedPartSecurityEvent encryptedPartSecurityEvent = (EncryptedPartSecurityEvent) securityEvent;
                    assertNotNull(encryptedPartSecurityEvent.getXmlSecEvent());
                    assertNotNull(encryptedPartSecurityEvent.getSecurityToken());
                    assertNotNull(encryptedPartSecurityEvent.getElementPath());
                    final QName expectedElementName = new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body");
                    assertEquals(encryptedPartSecurityEvent.getXmlSecEvent().asStartElement().getName(), expectedElementName);
                    assertEquals(encryptedPartSecurityEvent.getElementPath().size(), 2);
                    assertEquals(encryptedPartSecurityEvent.getElementPath().get(encryptedPartSecurityEvent.getElementPath().size() - 1), expectedElementName);
                }
            }

            EncryptedPartSecurityEvent encryptedPartSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.ENCRYPTED_PART);
            OperationSecurityEvent operationSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.OPERATION);
            String encryptedPartCorrelationID = encryptedPartSecurityEvent.getCorrelationID();
            String operationCorrelationID = operationSecurityEvent.getCorrelationID();

            List<SecurityEvent> operationSecurityEvents = new ArrayList<>();
            List<SecurityEvent> encryptedPartSecurityEvents = new ArrayList<>();

            List<SecurityEvent> securityEvents = securityEventListener.getReceivedSecurityEvents();
            for (int i = 0; i < securityEvents.size(); i++) {
                SecurityEvent securityEvent = securityEvents.get(i);
                if (securityEvent.getCorrelationID().equals(encryptedPartCorrelationID)) {
                    encryptedPartSecurityEvents.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(operationCorrelationID)) {
                    operationSecurityEvents.add(securityEvent);
                }
            }

            assertEquals(4, encryptedPartSecurityEvents.size());
            assertEquals(securityEventListener.getReceivedSecurityEvents().size(),
                    operationSecurityEvents.size() + encryptedPartSecurityEvents.size());
        }
    }

    @Test
    public void testEncDecryptionPartsContentOutbound() throws Exception {

        ByteArrayOutputStream baos;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.ENCRYPTION);
            securityProperties.setActions(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.addEncryptionPart(new SecurePart(new QName("http://www.w3.org/1999/XMLSchema", "complexType"), SecurePart.Modifier.Content));

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_DataReference.getNamespaceURI(), WSSConstants.TAG_xenc_DataReference.getLocalPart());
            assertEquals(nodeList.getLength(), 25);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 25);

            for (int i = 0; i < nodeList.getLength(); i++) {
                assertEquals(nodeList.item(i).getParentNode().getLocalName(), "complexType");
                assertEquals(nodeList.item(i).getParentNode().getNamespaceURI(), "http://www.w3.org/1999/XMLSchema");
                NodeList childNodes = nodeList.item(i).getParentNode().getChildNodes();
                for (int j = 0; j < childNodes.getLength(); j++) {
                    Node child = childNodes.item(j);
                    if (child.getNodeType() == Node.TEXT_NODE) {
                        assertEquals(child.getTextContent().trim(), "");
                    } else if (child.getNodeType() == Node.ELEMENT_NODE) {
                        assertEquals(child, nodeList.item(i));
                    } else {
                        fail("Unexpected Node encountered");
                    }
                }
            }
        }

        //done encryption; now test decryption:
        {
            String action = WSHandlerConstants.ENCRYPTION;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testEncDecryptionPartsContentInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.ENCRYPTION;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.ENCRYPTION_PARTS, "{Content}{http://www.w3.org/1999/XMLSchema}simpleType;");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }
        //test streaming decryption
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            WSSecurityEventConstants.Event[] expectedSecurityEvents = new WSSecurityEventConstants.Event[]{
                    WSSecurityEventConstants.X509Token,
                    WSSecurityEventConstants.OPERATION,
                    WSSecurityEventConstants.X509Token,
                    WSSecurityEventConstants.ContentEncrypted,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.EncryptedKeyToken,
                    WSSecurityEventConstants.ContentEncrypted,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.EncryptedKeyToken,
                    WSSecurityEventConstants.ContentEncrypted,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.EncryptedKeyToken,
                    WSSecurityEventConstants.ContentEncrypted,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.EncryptedKeyToken,
                    WSSecurityEventConstants.ContentEncrypted,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.EncryptedKeyToken,
                    WSSecurityEventConstants.ContentEncrypted,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.EncryptedKeyToken,
                    WSSecurityEventConstants.ContentEncrypted,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.EncryptedKeyToken,
                    WSSecurityEventConstants.ContentEncrypted,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.EncryptedKeyToken,
                    WSSecurityEventConstants.ContentEncrypted,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.EncryptedKeyToken,
                    WSSecurityEventConstants.ContentEncrypted,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.EncryptedKeyToken,
                    WSSecurityEventConstants.ContentEncrypted,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.EncryptedKeyToken,
                    WSSecurityEventConstants.ContentEncrypted,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.EncryptedKeyToken,
                    WSSecurityEventConstants.ContentEncrypted,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.EncryptedKeyToken,
                    WSSecurityEventConstants.ContentEncrypted,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.EncryptedKeyToken,
                    WSSecurityEventConstants.ContentEncrypted,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.EncryptedKeyToken,
                    WSSecurityEventConstants.ContentEncrypted,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.EncryptedKeyToken,
                    WSSecurityEventConstants.ContentEncrypted,
                    WSSecurityEventConstants.AlgorithmSuite,
            };
            final TestSecurityEventListener securityEventListener = new TestSecurityEventListener(expectedSecurityEvents);

            Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), securityEventListener);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 0);

            securityEventListener.compare();

            List<SecurityEvent> receivedSecurityEvents = securityEventListener.getReceivedSecurityEvents();
            for (int i = 0; i < receivedSecurityEvents.size(); i++) {
                SecurityEvent securityEvent = receivedSecurityEvents.get(i);
                if (securityEvent.getSecurityEventType() == WSSecurityEventConstants.OPERATION) {
                    OperationSecurityEvent operationSecurityEvent = (OperationSecurityEvent) securityEvent;
                    assertEquals(operationSecurityEvent.getOperation(), new QName("http://schemas.xmlsoap.org/wsdl/", "definitions"));
                } else if (securityEvent.getSecurityEventType() == WSSecurityEventConstants.ContentEncrypted) {
                    ContentEncryptedElementSecurityEvent contentEncryptedElementSecurityEvent = (ContentEncryptedElementSecurityEvent) securityEvent;
                    assertNotNull(contentEncryptedElementSecurityEvent.getXmlSecEvent());
                    assertNotNull(contentEncryptedElementSecurityEvent.getSecurityToken());
                    assertNotNull(contentEncryptedElementSecurityEvent.getElementPath());
                    final QName expectedElementName = new QName("http://www.w3.org/1999/XMLSchema", "simpleType");
                    assertEquals(contentEncryptedElementSecurityEvent.getXmlSecEvent().asStartElement().getName(), expectedElementName);
                    assertEquals(contentEncryptedElementSecurityEvent.getElementPath().size(), 6);
                    assertEquals(contentEncryptedElementSecurityEvent.getElementPath().get(contentEncryptedElementSecurityEvent.getElementPath().size() - 1), expectedElementName);
                }
            }

            List<ContentEncryptedElementSecurityEvent> contentEncryptedElementSecurityEventList = securityEventListener.getSecurityEvents(SecurityEventConstants.ContentEncrypted);
            OperationSecurityEvent operationSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.OPERATION);
            String encryptedPartCorrelationID1 = contentEncryptedElementSecurityEventList.get(0).getCorrelationID();
            String encryptedPartCorrelationID2 = contentEncryptedElementSecurityEventList.get(1).getCorrelationID();
            String encryptedPartCorrelationID3 = contentEncryptedElementSecurityEventList.get(2).getCorrelationID();
            String encryptedPartCorrelationID4 = contentEncryptedElementSecurityEventList.get(3).getCorrelationID();
            String encryptedPartCorrelationID5 = contentEncryptedElementSecurityEventList.get(4).getCorrelationID();
            String encryptedPartCorrelationID6 = contentEncryptedElementSecurityEventList.get(5).getCorrelationID();
            String encryptedPartCorrelationID7 = contentEncryptedElementSecurityEventList.get(6).getCorrelationID();
            String encryptedPartCorrelationID8 = contentEncryptedElementSecurityEventList.get(7).getCorrelationID();
            String encryptedPartCorrelationID9 = contentEncryptedElementSecurityEventList.get(8).getCorrelationID();
            String encryptedPartCorrelationID10 = contentEncryptedElementSecurityEventList.get(9).getCorrelationID();
            String encryptedPartCorrelationID11 = contentEncryptedElementSecurityEventList.get(10).getCorrelationID();
            String encryptedPartCorrelationID12 = contentEncryptedElementSecurityEventList.get(11).getCorrelationID();
            String encryptedPartCorrelationID13 = contentEncryptedElementSecurityEventList.get(12).getCorrelationID();
            String encryptedPartCorrelationID14 = contentEncryptedElementSecurityEventList.get(13).getCorrelationID();
            String encryptedPartCorrelationID15 = contentEncryptedElementSecurityEventList.get(14).getCorrelationID();
            String encryptedPartCorrelationID16 = contentEncryptedElementSecurityEventList.get(15).getCorrelationID();
            String encryptedPartCorrelationID17 = contentEncryptedElementSecurityEventList.get(16).getCorrelationID();
            String operationCorrelationID = operationSecurityEvent.getCorrelationID();

            List<SecurityEvent> operationSecurityEvents = new ArrayList<>();
            List<SecurityEvent> encryptedPartSecurityEvents1 = new ArrayList<>();
            List<SecurityEvent> encryptedPartSecurityEvents2 = new ArrayList<>();
            List<SecurityEvent> encryptedPartSecurityEvents3 = new ArrayList<>();
            List<SecurityEvent> encryptedPartSecurityEvents4 = new ArrayList<>();
            List<SecurityEvent> encryptedPartSecurityEvents5 = new ArrayList<>();
            List<SecurityEvent> encryptedPartSecurityEvents6 = new ArrayList<>();
            List<SecurityEvent> encryptedPartSecurityEvents7 = new ArrayList<>();
            List<SecurityEvent> encryptedPartSecurityEvents8 = new ArrayList<>();
            List<SecurityEvent> encryptedPartSecurityEvents9 = new ArrayList<>();
            List<SecurityEvent> encryptedPartSecurityEvents10 = new ArrayList<>();
            List<SecurityEvent> encryptedPartSecurityEvents11 = new ArrayList<>();
            List<SecurityEvent> encryptedPartSecurityEvents12 = new ArrayList<>();
            List<SecurityEvent> encryptedPartSecurityEvents13 = new ArrayList<>();
            List<SecurityEvent> encryptedPartSecurityEvents14 = new ArrayList<>();
            List<SecurityEvent> encryptedPartSecurityEvents15 = new ArrayList<>();
            List<SecurityEvent> encryptedPartSecurityEvents16 = new ArrayList<>();
            List<SecurityEvent> encryptedPartSecurityEvents17 = new ArrayList<>();

            List<SecurityEvent> securityEvents = securityEventListener.getReceivedSecurityEvents();
            for (int i = 0; i < securityEvents.size(); i++) {
                SecurityEvent securityEvent = securityEvents.get(i);
                if (securityEvent.getCorrelationID().equals(operationCorrelationID)) {
                    operationSecurityEvents.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(encryptedPartCorrelationID1)) {
                    encryptedPartSecurityEvents1.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(encryptedPartCorrelationID2)) {
                    encryptedPartSecurityEvents2.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(encryptedPartCorrelationID3)) {
                    encryptedPartSecurityEvents3.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(encryptedPartCorrelationID4)) {
                    encryptedPartSecurityEvents4.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(encryptedPartCorrelationID5)) {
                    encryptedPartSecurityEvents5.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(encryptedPartCorrelationID6)) {
                    encryptedPartSecurityEvents6.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(encryptedPartCorrelationID7)) {
                    encryptedPartSecurityEvents7.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(encryptedPartCorrelationID8)) {
                    encryptedPartSecurityEvents8.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(encryptedPartCorrelationID9)) {
                    encryptedPartSecurityEvents9.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(encryptedPartCorrelationID10)) {
                    encryptedPartSecurityEvents10.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(encryptedPartCorrelationID11)) {
                    encryptedPartSecurityEvents11.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(encryptedPartCorrelationID12)) {
                    encryptedPartSecurityEvents12.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(encryptedPartCorrelationID13)) {
                    encryptedPartSecurityEvents13.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(encryptedPartCorrelationID14)) {
                    encryptedPartSecurityEvents14.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(encryptedPartCorrelationID15)) {
                    encryptedPartSecurityEvents15.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(encryptedPartCorrelationID16)) {
                    encryptedPartSecurityEvents16.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(encryptedPartCorrelationID17)) {
                    encryptedPartSecurityEvents17.add(securityEvent);
                }
            }

            assertEquals(4, encryptedPartSecurityEvents1.size());
            assertEquals(3, encryptedPartSecurityEvents2.size());
            assertEquals(3, encryptedPartSecurityEvents3.size());
            assertEquals(3, encryptedPartSecurityEvents4.size());
            assertEquals(3, encryptedPartSecurityEvents5.size());
            assertEquals(3, encryptedPartSecurityEvents6.size());
            assertEquals(3, encryptedPartSecurityEvents7.size());
            assertEquals(3, encryptedPartSecurityEvents8.size());
            assertEquals(3, encryptedPartSecurityEvents9.size());
            assertEquals(3, encryptedPartSecurityEvents10.size());
            assertEquals(3, encryptedPartSecurityEvents11.size());
            assertEquals(3, encryptedPartSecurityEvents12.size());
            assertEquals(3, encryptedPartSecurityEvents13.size());
            assertEquals(3, encryptedPartSecurityEvents14.size());
            assertEquals(3, encryptedPartSecurityEvents15.size());
            assertEquals(3, encryptedPartSecurityEvents16.size());
            assertEquals(3, encryptedPartSecurityEvents17.size());
            assertEquals(securityEventListener.getReceivedSecurityEvents().size(),
                    operationSecurityEvents.size() +
                    encryptedPartSecurityEvents1.size() +
                    encryptedPartSecurityEvents2.size() +
                    encryptedPartSecurityEvents3.size() +
                    encryptedPartSecurityEvents4.size() +
                    encryptedPartSecurityEvents5.size() +
                    encryptedPartSecurityEvents6.size() +
                    encryptedPartSecurityEvents7.size() +
                    encryptedPartSecurityEvents8.size() +
                    encryptedPartSecurityEvents9.size() +
                    encryptedPartSecurityEvents10.size() +
                    encryptedPartSecurityEvents11.size() +
                    encryptedPartSecurityEvents12.size() +
                    encryptedPartSecurityEvents13.size() +
                    encryptedPartSecurityEvents14.size() +
                    encryptedPartSecurityEvents15.size() +
                    encryptedPartSecurityEvents16.size() +
                    encryptedPartSecurityEvents17.size() + 1 //plus one because of the
                    // X509TokenEvent which can't be correlated that easy for this use case
            );
        }
    }

    @Test
    public void testEncDecryptionPartsElementOutbound() throws Exception {

        ByteArrayOutputStream baos;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.ENCRYPTION);
            securityProperties.setActions(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.addEncryptionPart(new SecurePart(new QName("http://www.w3.org/1999/XMLSchema", "complexType"), SecurePart.Modifier.Element));

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 25);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_DataReference.getNamespaceURI(), WSSConstants.TAG_xenc_DataReference.getLocalPart());
            assertEquals(nodeList.getLength(), 25);

            nodeList = document.getElementsByTagNameNS("http://www.w3.org/1999/XMLSchema", "complexType");
            assertEquals(nodeList.getLength(), 0);
        }

        //done encryption; now test decryption:
        {
            String action = WSHandlerConstants.ENCRYPTION;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testEncDecryptionPartsHeaderOutbound() throws Exception {

        ByteArrayOutputStream baos;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.ENCRYPTION);
            securityProperties.setActions(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.addEncryptionPart(new SecurePart(new QName("http://www.w3.org/1999/XMLSchema", "complexType"), SecurePart.Modifier.Element));
            securityProperties.addEncryptionPart(new SecurePart(new QName("http://www.example.com", "testEncryptedHeader"), SecurePart.Modifier.Element));

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-encryptedHeader.xml");

            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 27);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_DataReference.getNamespaceURI(), WSSConstants.TAG_xenc_DataReference.getLocalPart());
            assertEquals(nodeList.getLength(), 26);

            nodeList = document.getElementsByTagNameNS("http://www.w3.org/1999/XMLSchema", "complexType");
            assertEquals(nodeList.getLength(), 0);
        }

        //done encryption; now test decryption:
        {
            String action = WSHandlerConstants.ENCRYPTION;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testEncDecryptionPartsElementInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.ENCRYPTION;
            Properties properties = new Properties();

            properties.setProperty(WSHandlerConstants.ENCRYPTION_PARTS, "{Element}{http://www.w3.org/1999/XMLSchema}simpleType;");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done encryption; now test decryption:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            WSSecurityEventConstants.Event[] expectedSecurityEvents = new WSSecurityEventConstants.Event[]{
                    WSSecurityEventConstants.X509Token,
                    WSSecurityEventConstants.OPERATION,
                    WSSecurityEventConstants.X509Token,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.EncryptedElement,
                    WSSecurityEventConstants.EncryptedKeyToken,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.EncryptedElement,
                    WSSecurityEventConstants.EncryptedKeyToken,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.EncryptedElement,
                    WSSecurityEventConstants.EncryptedKeyToken,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.EncryptedElement,
                    WSSecurityEventConstants.EncryptedKeyToken,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.EncryptedElement,
                    WSSecurityEventConstants.EncryptedKeyToken,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.EncryptedElement,
                    WSSecurityEventConstants.EncryptedKeyToken,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.EncryptedElement,
                    WSSecurityEventConstants.EncryptedKeyToken,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.EncryptedElement,
                    WSSecurityEventConstants.EncryptedKeyToken,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.EncryptedElement,
                    WSSecurityEventConstants.EncryptedKeyToken,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.EncryptedElement,
                    WSSecurityEventConstants.EncryptedKeyToken,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.EncryptedElement,
                    WSSecurityEventConstants.EncryptedKeyToken,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.EncryptedElement,
                    WSSecurityEventConstants.EncryptedKeyToken,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.EncryptedElement,
                    WSSecurityEventConstants.EncryptedKeyToken,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.EncryptedElement,
                    WSSecurityEventConstants.EncryptedKeyToken,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.EncryptedElement,
                    WSSecurityEventConstants.EncryptedKeyToken,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.EncryptedElement,
                    WSSecurityEventConstants.EncryptedKeyToken,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.EncryptedElement,
            };
            final TestSecurityEventListener securityEventListener = new TestSecurityEventListener(expectedSecurityEvents);

            Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), securityEventListener);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 0);

            securityEventListener.compare();

            List<SecurityEvent> receivedSecurityEvents = securityEventListener.getReceivedSecurityEvents();
            for (int i = 0; i < receivedSecurityEvents.size(); i++) {
                SecurityEvent securityEvent = receivedSecurityEvents.get(i);
                if (securityEvent.getSecurityEventType() == WSSecurityEventConstants.OPERATION) {
                    OperationSecurityEvent operationSecurityEvent = (OperationSecurityEvent) securityEvent;
                    assertEquals(operationSecurityEvent.getOperation(), new QName("http://schemas.xmlsoap.org/wsdl/", "definitions"));
                } else if (securityEvent.getSecurityEventType() == WSSecurityEventConstants.EncryptedElement) {
                    EncryptedElementSecurityEvent encryptedElementSecurityEvent = (EncryptedElementSecurityEvent) securityEvent;
                    assertNotNull(encryptedElementSecurityEvent.getXmlSecEvent());
                    assertNotNull(encryptedElementSecurityEvent.getSecurityToken());
                    assertNotNull(encryptedElementSecurityEvent.getElementPath());
                    final QName expectedElementName = new QName("http://www.w3.org/1999/XMLSchema", "simpleType");
                    assertEquals(encryptedElementSecurityEvent.getXmlSecEvent().asStartElement().getName(), expectedElementName);
                    assertEquals(encryptedElementSecurityEvent.getElementPath().size(), 6);
                    assertEquals(encryptedElementSecurityEvent.getElementPath().get(encryptedElementSecurityEvent.getElementPath().size() - 1), expectedElementName);
                }
            }
        }
    }

    @Test
    public void testEncDecryptionPartsHeaderInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-encryptedHeader.xml");
            String action = WSHandlerConstants.ENCRYPTION;
            Properties properties = new Properties();

            properties.setProperty(WSHandlerConstants.ENCRYPTION_PARTS, "{Header}{http://www.example.com}testEncryptedHeader;");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done encryption; now test decryption:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            WSSecurityEventConstants.Event[] expectedSecurityEvents = new WSSecurityEventConstants.Event[]{
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.X509Token,
                    WSSecurityEventConstants.ENCRYPTED_PART,
                    WSSecurityEventConstants.OPERATION,
            };
            final TestSecurityEventListener securityEventListener = new TestSecurityEventListener(expectedSecurityEvents);

            Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), securityEventListener);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_wsse11_EncryptedHeader.getNamespaceURI(), WSSConstants.TAG_wsse11_EncryptedHeader.getLocalPart());
            assertEquals(nodeList.getLength(), 1);

            securityEventListener.compare();

            List<SecurityEvent> receivedSecurityEvents = securityEventListener.getReceivedSecurityEvents();
            for (int i = 0; i < receivedSecurityEvents.size(); i++) {
                SecurityEvent securityEvent = receivedSecurityEvents.get(i);
                if (securityEvent.getSecurityEventType() == WSSecurityEventConstants.OPERATION) {
                    OperationSecurityEvent operationSecurityEvent = (OperationSecurityEvent) securityEvent;
                    assertEquals(operationSecurityEvent.getOperation(), new QName("http://schemas.xmlsoap.org/wsdl/", "definitions"));
                } else if (securityEvent.getSecurityEventType() == WSSecurityEventConstants.ENCRYPTED_PART) {
                    EncryptedPartSecurityEvent encryptedPartSecurityEvent = (EncryptedPartSecurityEvent) securityEvent;
                    assertNotNull(encryptedPartSecurityEvent.getXmlSecEvent());
                    assertNotNull(encryptedPartSecurityEvent.getSecurityToken());
                    assertNotNull(encryptedPartSecurityEvent.getElementPath());
                    final QName expectedElementName = new QName("http://www.example.com", "testEncryptedHeader");
                    assertEquals(encryptedPartSecurityEvent.getXmlSecEvent().asStartElement().getName(), expectedElementName);
                    assertEquals(encryptedPartSecurityEvent.getElementPath().size(), 3);
                    assertEquals(encryptedPartSecurityEvent.getElementPath().get(encryptedPartSecurityEvent.getElementPath().size() - 1), expectedElementName);
                }
            }

            EncryptedPartSecurityEvent encryptedPartSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.ENCRYPTED_PART);
            OperationSecurityEvent operationSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.OPERATION);
            String encryptedPartCorrelationID = encryptedPartSecurityEvent.getCorrelationID();
            String operationCorrelationID = operationSecurityEvent.getCorrelationID();

            List<SecurityEvent> operationSecurityEvents = new ArrayList<>();
            List<SecurityEvent> encryptedPartSecurityEvents = new ArrayList<>();

            List<SecurityEvent> securityEvents = securityEventListener.getReceivedSecurityEvents();
            for (int i = 0; i < securityEvents.size(); i++) {
                SecurityEvent securityEvent = securityEvents.get(i);
                if (securityEvent.getCorrelationID().equals(encryptedPartCorrelationID)) {
                    encryptedPartSecurityEvents.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(operationCorrelationID)) {
                    operationSecurityEvents.add(securityEvent);
                }
            }

            assertEquals(4, encryptedPartSecurityEvents.size());
            assertEquals(securityEventListener.getReceivedSecurityEvents().size(),
                    operationSecurityEvents.size() + encryptedPartSecurityEvents.size());
        }
    }

    @Test
    public void testExceptionOnElementToEncryptNotFound() throws Exception {

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.ENCRYPTION);
            securityProperties.setActions(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.addEncryptionPart(new SecurePart(new QName("http://www.wrongnamespace.org", "complexType"), SecurePart.Modifier.Content));

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            try {
                doOutboundSecurity(securityProperties, sourceDocument);
                fail("Exception expected");
            } catch (XMLStreamException e) {
                assertTrue(e.getCause() instanceof XMLSecurityException);
                assertEquals("Part to encrypt not found: {http://www.wrongnamespace.org}complexType", e.getCause().getMessage());
            }
        }
    }

    @Test
    public void testEncDecryptionUseThisCert() throws Exception {

        ByteArrayOutputStream baos;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.ENCRYPTION);
            securityProperties.setActions(actions);

            KeyStore keyStore = KeyStore.getInstance("jks");
            keyStore.load(this.getClass().getClassLoader().getResourceAsStream("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUseThisCertificate((X509Certificate) keyStore.getCertificate("receiver"));

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_DataReference.getNamespaceURI(), WSSConstants.TAG_xenc_DataReference.getLocalPart());
            assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 1);

            assertEquals(nodeList.item(0).getParentNode().getLocalName(), "Body");
            NodeList childNodes = nodeList.item(0).getParentNode().getChildNodes();
            for (int i = 0; i < childNodes.getLength(); i++) {
                Node child = childNodes.item(i);
                if (child.getNodeType() == Node.TEXT_NODE) {
                    assertEquals(child.getTextContent().trim(), "");
                } else if (child.getNodeType() == Node.ELEMENT_NODE) {
                    assertEquals(child, nodeList.item(0));
                } else {
                    fail("Unexpected Node encountered");
                }
            }
        }

        //done encryption; now test decryption:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, new ByteArrayInputStream(baos.toByteArray()));

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 0);
        }
    }

    @Test
    public void testEncDecryptionKeyIdentifierIssuerSerialOutbound() throws Exception {

        ByteArrayOutputStream baos;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.ENCRYPTION);
            securityProperties.setActions(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionKeyIdentifier(WSSecurityTokenConstants.KeyIdentifier_IssuerSerial);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            XPathExpression xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey/dsig:KeyInfo/wsse:SecurityTokenReference/dsig:X509Data/dsig:X509IssuerSerial/dsig:X509SerialNumber");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_DataReference.getNamespaceURI(), WSSConstants.TAG_xenc_DataReference.getLocalPart());
            assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
        }

        //done encryption; now test decryption:
        {
            String action = WSHandlerConstants.ENCRYPTION;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testEncDecryptionKeyIdentifierIssuerSerialInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.ENCRYPTION;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.ENC_KEY_ID, "IssuerSerial");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey/dsig:KeyInfo/wsse:SecurityTokenReference/dsig:X509Data/dsig:X509IssuerSerial/dsig:X509SerialNumber");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            assertNotNull(node);

            Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done encryption; now test decryption:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 0);
        }
    }

    @Test
    public void testEncDecryptionKeyIdentifierBinarySecurityTokenDirectReferenceOutbound() throws Exception {

        ByteArrayOutputStream baos;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.ENCRYPTION);
            securityProperties.setActions(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionKeyIdentifier(WSSecurityTokenConstants.KEYIDENTIFIER_SECURITY_TOKEN_DIRECT_REFERENCE);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            XPathExpression xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/wsse:BinarySecurityToken");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_DataReference.getNamespaceURI(), WSSConstants.TAG_xenc_DataReference.getLocalPart());
            assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
        }

        //done encryption; now test decryption:
        {
            String action = WSHandlerConstants.ENCRYPTION;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testEncDecryptionKeyIdentifierBinarySecurityTokenDirectReferenceInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.ENCRYPTION;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.ENC_KEY_ID, "DirectReference");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/wsse:BinarySecurityToken");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            assertNotNull(node);

            Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done encryption; now test decryption:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 0);
        }
    }

    /**
     * not possible with swssf atm
     *
     * @Test public void testEncDecryptionKeyIdentifierBinarySecurityTokenDirectReferenceAtTheEndOfTheSecurityHeaderInbound() throws Exception {
     * <p/>
     * ByteArrayOutputStream baos = new ByteArrayOutputStream();
     * {
     * InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
     * String action = WSHandlerConstants.ENCRYPTION;
     * Properties properties = new Properties();
     * properties.setProperty(WSHandlerConstants.ENC_KEY_ID, "DirectReference");
     * Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);
     * <p/>
     * //some test that we can really sure we get what we want from WSS4J
     * XPathExpression xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/wsse:BinarySecurityToken");
     * Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
     * assertNotNull(node);
     * Element parentElement = (Element) node.getParentNode();
     * parentElement.removeChild(node);
     * parentElement.appendChild(node);
     * <p/>
     * Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
     * transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
     * }
     * <p/>
     * //done encryption; now test decryption:
     * {
     * WSSSecurityProperties securityProperties = new WSSSecurityProperties();
     * securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
     * securityProperties.setCallbackHandler(new org.apache.wss4j.test.CallbackHandlerImpl());
     * Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));
     * <p/>
     * //header element must still be there
     * NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
     * assertEquals(nodeList.getLength(), 1);
     * assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());
     * <p/>
     * //no encrypted content
     * nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
     * assertEquals(nodeList.getLength(), 0);
     * }
     * }
     */

/*  Not spec conform and therefore not supported!:
    public void testEncDecryptionKeyIdentifierBinarySecurityTokenEmbedded() throws Exception {

        ByteArrayOutputStream baos;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.ENCRYPTION};
            securityProperties.setActions(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionKeyIdentifierType(WSSConstants.WSSKeyIdentifierType.BST_EMBEDDED);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            XPathExpression xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:Reference/wsse:BinarySecurityToken");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_DataReference.getNamespaceURI(), WSSConstants.TAG_xenc_DataReference.getLocalPart());
            assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
        }

        //done encryption; now test decryption:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, new ByteArrayInputStream(baos.toByteArray()));

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 0);
        }
    }*/

    @Test
    public void testEncDecryptionKeyIdentifierX509KeyOutbound() throws Exception {

        ByteArrayOutputStream baos;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.ENCRYPTION);
            securityProperties.setActions(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionKeyIdentifier(WSSecurityTokenConstants.KeyIdentifier_X509KeyIdentifier);
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            XPathExpression xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:KeyIdentifier[@ValueType='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3']");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_DataReference.getNamespaceURI(), WSSConstants.TAG_xenc_DataReference.getLocalPart());
            assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
        }

        //done encryption; now test decryption:
        {
            String action = WSHandlerConstants.ENCRYPTION;
            Properties properties = new Properties();
            doInboundSecurityWithWSS4J_1(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action, properties, false);
        }
    }

    @Test
    public void testEncDecryptionKeyIdentifierX509KeyInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.ENCRYPTION;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.ENC_KEY_ID, "X509KeyIdentifier");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:KeyIdentifier[@ValueType='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3']");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            assertNotNull(node);

            Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done encryption; now test decryption:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 0);
        }
    }

    @Test
    public void testEncDecryptionKeyIdentifierSubjectKeyOutbound() throws Exception {

        ByteArrayOutputStream baos;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.ENCRYPTION);
            securityProperties.setActions(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionKeyIdentifier(WSSecurityTokenConstants.KeyIdentifier_SkiKeyIdentifier);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            XPathExpression xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:KeyIdentifier[@ValueType='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier']");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_DataReference.getNamespaceURI(), WSSConstants.TAG_xenc_DataReference.getLocalPart());
            assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
        }

        //done encryption; now test decryption:
        {
            String action = WSHandlerConstants.ENCRYPTION;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testEncDecryptionKeyIdentifierSubjectKeyInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.ENCRYPTION;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.ENC_KEY_ID, "SKIKeyIdentifier");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:KeyIdentifier[@ValueType='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier']");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            assertNotNull(node);

            Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done encryption; now test decryption:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 0);
        }
    }

    @Test
    public void testEncDecryptionKeyIdentifierThumbprintOutbound() throws Exception {

        ByteArrayOutputStream baos;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.ENCRYPTION);
            securityProperties.setActions(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionKeyIdentifier(WSSecurityTokenConstants.KEYIDENTIFIER_THUMBPRINT_IDENTIFIER);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            XPathExpression xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:KeyIdentifier[@ValueType='http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1']");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_DataReference.getNamespaceURI(), WSSConstants.TAG_xenc_DataReference.getLocalPart());
            assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
        }

        //done encryption; now test decryption:
        {
            String action = WSHandlerConstants.ENCRYPTION;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testEncDecryptionKeyIdentifierThumbprintInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.ENCRYPTION;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.ENC_KEY_ID, "Thumbprint");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:KeyIdentifier[@ValueType='http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1']");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            assertNotNull(node);

            Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done encryption; now test decryption:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 0);
        }
    }

    @Test
    public void testEncDecryptionKeyIdentifierSHA1Outbound() throws Exception {

        ByteArrayOutputStream baos;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.ENCRYPTION);
            securityProperties.setActions(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionKeyIdentifier(WSSecurityTokenConstants.KEYIDENTIFIER_ENCRYPTED_KEY_SHA1_IDENTIFIER);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            XPathExpression xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:KeyIdentifier[@ValueType='http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1']");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            assertNotNull(node);

            xPathExpression = getXPath("/soap:Envelope/soap:Body/xenc:EncryptedData/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:KeyIdentifier[@ValueType='http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKeySHA1']");
            node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_DataReference.getNamespaceURI(), WSSConstants.TAG_xenc_DataReference.getLocalPart());
            assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
        }

        //done encryption; now test decryption:
        {
            String action = WSHandlerConstants.ENCRYPTION;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testEncDecryptionKeyIdentifierSHA1Inbound() throws Exception {

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey key = keyGen.generateKey();

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

            Document doc = documentBuilderFactory.newDocumentBuilder().parse(sourceDocument);

            WSSecHeader secHeader = new WSSecHeader(doc);
            secHeader.insertSecurityHeader();

            WSSecEncrypt builder = new WSSecEncrypt(secHeader);
            builder.setKeyIdentifierType(WSConstants.ENCRYPTED_KEY_SHA1_IDENTIFIER);
            builder.setEncryptSymmKey(false);
            Document securedDocument = builder.build(null, key);

            XPathExpression xPathExpression = getXPath("/soap:Envelope/soap:Body/xenc:EncryptedData/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:KeyIdentifier[@ValueType='http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKeySHA1']");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            assertNotNull(node);

            Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done encryption; now test decryption:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl(key.getEncoded()));
            Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            //no encrypted content
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 0);
        }
    }

    @Test
    public void testDecryptionReferenceListOutsideEncryptedKey() throws Exception {

        ByteArrayOutputStream baos;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.ENCRYPTION);
            securityProperties.setActions(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionKeyIdentifier(WSSecurityTokenConstants.KeyIdentifier_IssuerSerial);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            XPathExpression xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey/dsig:KeyInfo/wsse:SecurityTokenReference/dsig:X509Data/dsig:X509IssuerSerial/dsig:X509SerialNumber");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_DataReference.getNamespaceURI(), WSSConstants.TAG_xenc_DataReference.getLocalPart());
            assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 1);

            //move ReferenceList...
            TransformerFactory transFact = TransformerFactory.newInstance();
            Transformer trans = transFact.newTransformer(new StreamSource(this.getClass().getClassLoader().getResourceAsStream("xsl/testDecryptionReferenceListOutsideEncryptedKey.xsl")));
            baos.reset();
            trans.transform(new DOMSource(document), new StreamResult(baos));

        }

        //done encryption; now test decryption:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, new ByteArrayInputStream(baos.toByteArray()));

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 0);
        }
    }

    @Test
    public void testEncDecryptionSuperEncryptionInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.ENCRYPTION;
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, new Properties());

            Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));

            securedDocument = doOutboundSecurityWithWSS4J(new ByteArrayInputStream(baos.toByteArray()), action, new Properties());

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p']");
            NodeList nodeList = (NodeList) xPathExpression.evaluate(securedDocument, XPathConstants.NODESET);
            assertEquals(nodeList.getLength(), 2);

            transformer = TRANSFORMER_FACTORY.newTransformer();
            baos.reset();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }
        //test streaming decryption
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.getLength(), 2);
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 0);
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testCompressedEncDecryption() throws Exception {

        Init.init(WSSec.class.getClassLoader().getResource("wss/wss-config.xml").toURI(), WSSec.class);
        Field algorithmsClassMapField = TransformerAlgorithmMapper.class.getDeclaredField("algorithmsClassMapOut");
        algorithmsClassMapField.setAccessible(true);
        Map<String, Class<?>> map = (Map<String, Class<?>>)algorithmsClassMapField.get(null);
        map.put("http://www.apache.org/2012/04/xmlsec/gzip", GzipCompressorOutputStream.class);
        algorithmsClassMapField = TransformerAlgorithmMapper.class.getDeclaredField("algorithmsClassMapIn");
        algorithmsClassMapField.setAccessible(true);
        map = (Map<String, Class<?>>)algorithmsClassMapField.get(null);
        map.put("http://www.apache.org/2012/04/xmlsec/gzip", GzipCompressorInputStream.class);

        ByteArrayOutputStream baos;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.ENCRYPTION);
            securityProperties.setActions(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionCompressionAlgorithm("http://www.apache.org/2012/04/xmlsec/gzip");

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            XPathExpression xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p']");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_DataReference.getNamespaceURI(), WSSConstants.TAG_xenc_DataReference.getLocalPart());
            assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 1);

            xPathExpression = getXPath("/soap:Envelope/soap:Body/xenc:EncryptedData/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2001/04/xmlenc#aes256-cbc']");
            node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            assertNotNull(node);

            assertEquals(node.getParentNode().getParentNode().getLocalName(), "Body");
            NodeList childNodes = node.getParentNode().getParentNode().getChildNodes();
            for (int i = 0; i < childNodes.getLength(); i++) {
                Node child = childNodes.item(i);
                if (child.getNodeType() == Node.TEXT_NODE) {
                    assertEquals(child.getTextContent().trim(), "");
                } else if (child.getNodeType() == Node.ELEMENT_NODE) {
                    assertEquals(child, nodeList.item(0));
                } else {
                    fail("Unexpected Node encountered");
                }
            }
        }

        //done encryption; now test decryption:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            WSSecurityEventConstants.Event[] expectedSecurityEvents = new WSSecurityEventConstants.Event[]{
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.X509Token,
                    WSSecurityEventConstants.ENCRYPTED_PART,
                    WSSecurityEventConstants.OPERATION,
            };
            final TestSecurityEventListener securityEventListener = new TestSecurityEventListener(expectedSecurityEvents);

            Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), securityEventListener);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 0);

            securityEventListener.compare();

            List<SecurityEvent> receivedSecurityEvents = securityEventListener.getReceivedSecurityEvents();
            for (int i = 0; i < receivedSecurityEvents.size(); i++) {
                SecurityEvent securityEvent = receivedSecurityEvents.get(i);
                if (securityEvent.getSecurityEventType() == WSSecurityEventConstants.OPERATION) {
                    OperationSecurityEvent operationSecurityEvent = (OperationSecurityEvent) securityEvent;
                    assertEquals(operationSecurityEvent.getOperation(), new QName("http://schemas.xmlsoap.org/wsdl/", "definitions"));
                } else if (securityEvent.getSecurityEventType() == WSSecurityEventConstants.ENCRYPTED_PART) {
                    EncryptedPartSecurityEvent encryptedPartSecurityEvent = (EncryptedPartSecurityEvent) securityEvent;
                    assertNotNull(encryptedPartSecurityEvent.getXmlSecEvent());
                    assertNotNull(encryptedPartSecurityEvent.getSecurityToken());
                    assertNotNull(encryptedPartSecurityEvent.getElementPath());
                    final QName expectedElementName = new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body");
                    assertEquals(encryptedPartSecurityEvent.getXmlSecEvent().asStartElement().getName(), expectedElementName);
                    assertEquals(encryptedPartSecurityEvent.getElementPath().size(), 2);
                    assertEquals(encryptedPartSecurityEvent.getElementPath().get(encryptedPartSecurityEvent.getElementPath().size() - 1), expectedElementName);
                }
            }

            EncryptedPartSecurityEvent encryptedPartSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.ENCRYPTED_PART);
            OperationSecurityEvent operationSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.OPERATION);
            String encryptedPartCorrelationID = encryptedPartSecurityEvent.getCorrelationID();
            String operationCorrelationID = operationSecurityEvent.getCorrelationID();

            List<SecurityEvent> operationSecurityEvents = new ArrayList<>();
            List<SecurityEvent> encryptedPartSecurityEvents = new ArrayList<>();

            List<SecurityEvent> securityEvents = securityEventListener.getReceivedSecurityEvents();
            for (int i = 0; i < securityEvents.size(); i++) {
                SecurityEvent securityEvent = securityEvents.get(i);
                if (securityEvent.getCorrelationID().equals(encryptedPartCorrelationID)) {
                    encryptedPartSecurityEvents.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(operationCorrelationID)) {
                    operationSecurityEvents.add(securityEvent);
                }
            }

            assertEquals(4, encryptedPartSecurityEvents.size());
            assertEquals(securityEventListener.getReceivedSecurityEvents().size(),
                    operationSecurityEvents.size() + encryptedPartSecurityEvents.size());
        }
    }

    /**
     * rsa-oaep-mgf1p, Digest:SHA256, MGF:SHA1, PSource: None
     */
    @Test
    public void testKeyWrappingRSAOAEPMGF1AESGCM128Outbound() throws Exception {
        assumeFalse(isIBMJdK);
        try {
            Security.addProvider(new BouncyCastleProvider());
            ByteArrayOutputStream baos;
            {
                WSSSecurityProperties securityProperties = new WSSSecurityProperties();
                List<WSSConstants.Action> actions = new ArrayList<>();
                actions.add(WSSConstants.ENCRYPTION);
                securityProperties.setActions(actions);
                securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
                securityProperties.setEncryptionUser("receiver");
                securityProperties.setEncryptionSymAlgorithm("http://www.w3.org/2009/xmlenc11#aes128-gcm");
                securityProperties.setEncryptionKeyTransportAlgorithm("http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p");

                InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
                baos = doOutboundSecurity(securityProperties, sourceDocument);

                Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
                NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
                assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

                XPathExpression xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p']");
                Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
                assertNotNull(node);

                nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_DataReference.getNamespaceURI(), WSSConstants.TAG_xenc_DataReference.getLocalPart());
                assertEquals(nodeList.getLength(), 1);

                nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
                assertEquals(nodeList.getLength(), 1);

                xPathExpression = getXPath("/soap:Envelope/soap:Body/xenc:EncryptedData/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2009/xmlenc11#aes128-gcm']");
                node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
                assertNotNull(node);

                assertEquals(node.getParentNode().getParentNode().getLocalName(), "Body");
                NodeList childNodes = node.getParentNode().getParentNode().getChildNodes();
                for (int i = 0; i < childNodes.getLength(); i++) {
                    Node child = childNodes.item(i);
                    if (child.getNodeType() == Node.TEXT_NODE) {
                        assertEquals(child.getTextContent().trim(), "");
                    } else if (child.getNodeType() == Node.ELEMENT_NODE) {
                        assertEquals(child, nodeList.item(0));
                    } else {
                        fail("Unexpected Node encountered");
                    }
                }
            }

            //done encryption; now test decryption:
            {
                String action = WSHandlerConstants.ENCRYPTION;
                doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
            }
        } finally {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        }
    }

    @Test
    public void testKeyWrappingRSAOAEPMGF1AESGCM128Inbound() throws Exception {
        assumeFalse(isIBMJdK);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.ENCRYPTION;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.ENC_SYM_ALGO, "http://www.w3.org/2009/xmlenc11#aes128-gcm");
            properties.put(WSHandlerConstants.ENC_KEY_TRANSPORT, "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p']");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            assertNotNull(node);

            xPathExpression = getXPath("/soap:Envelope/soap:Body/xenc:EncryptedData/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2009/xmlenc11#aes128-gcm']");
            node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            assertNotNull(node);

            Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }
        //test streaming decryption
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 0);
        }
    }

    /**
    * rsa-oaep-mgf1p, Digest:SHA256, MGF:SHA1, PSource: None
    */
    @Test
    public void testKeyWrappingRSAOAEPAESGCM192SHA256Outbound() throws Exception {
        assumeFalse(isIBMJdK);
        try {
            Security.addProvider(new BouncyCastleProvider());
            ByteArrayOutputStream baos;
            {
                WSSSecurityProperties securityProperties = new WSSSecurityProperties();
                List<WSSConstants.Action> actions = new ArrayList<>();
                actions.add(WSSConstants.ENCRYPTION);
                securityProperties.setActions(actions);
                securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
                securityProperties.setEncryptionUser("receiver");
                securityProperties.setEncryptionSymAlgorithm("http://www.w3.org/2009/xmlenc11#aes192-gcm");
                securityProperties.setEncryptionKeyTransportAlgorithm("http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p");
                securityProperties.setEncryptionKeyTransportDigestAlgorithm("http://www.w3.org/2001/04/xmlenc#sha256");

                InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
                baos = doOutboundSecurity(securityProperties, sourceDocument);

                Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
                NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
                assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

                XPathExpression xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p']");
                Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
                assertNotNull(node);

                xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod/dsig:DigestMethod[@Algorithm='http://www.w3.org/2001/04/xmlenc#sha256']");
                node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
                assertNotNull(node);

                nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_DataReference.getNamespaceURI(), WSSConstants.TAG_xenc_DataReference.getLocalPart());
                assertEquals(nodeList.getLength(), 1);

                nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
                assertEquals(nodeList.getLength(), 1);

                xPathExpression = getXPath("/soap:Envelope/soap:Body/xenc:EncryptedData/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2009/xmlenc11#aes192-gcm']");
                node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
                assertNotNull(node);

                assertEquals(node.getParentNode().getParentNode().getLocalName(), "Body");
                NodeList childNodes = node.getParentNode().getParentNode().getChildNodes();
                for (int i = 0; i < childNodes.getLength(); i++) {
                    Node child = childNodes.item(i);
                    if (child.getNodeType() == Node.TEXT_NODE) {
                        assertEquals(child.getTextContent().trim(), "");
                    } else if (child.getNodeType() == Node.ELEMENT_NODE) {
                        assertEquals(child, nodeList.item(0));
                    } else {
                        fail("Unexpected Node encountered");
                    }
                }
            }
            //done encryption; now test decryption:
            {
                String action = WSHandlerConstants.ENCRYPTION;
                doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
            }
        } finally {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        }
    }

    @Test
    public void testKeyWrappingRSAOAEPAESGCM192SHA256Inbound() throws Exception {
        assumeFalse(isIBMJdK);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.ENCRYPTION;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.ENC_SYM_ALGO, "http://www.w3.org/2009/xmlenc11#aes192-gcm");
            properties.put(WSHandlerConstants.ENC_KEY_TRANSPORT, "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p");
            properties.put(WSHandlerConstants.ENC_DIGEST_ALGO, "http://www.w3.org/2001/04/xmlenc#sha256");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p']");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            assertNotNull(node);

            xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod/dsig:DigestMethod[@Algorithm='http://www.w3.org/2001/04/xmlenc#sha256']");
            node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            assertNotNull(node);

            xPathExpression = getXPath("/soap:Envelope/soap:Body/xenc:EncryptedData/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2009/xmlenc11#aes192-gcm']");
            node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            assertNotNull(node);

            Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }
        //test streaming decryption
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.addIgnoreBSPRule(BSPRule.R5620);

            Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 0);
        }
    }

    /**
     * rsa-oaep, Digest:SHA384, MGF:SHA1, PSource: None
     */
    @Test
    public void testKeyWrappingRSAOAEPAES192GCMSHA384MGF1sha384Outbound() throws Exception {
        assumeFalse(isIBMJdK);
        try {
            Security.addProvider(new BouncyCastleProvider());

            ByteArrayOutputStream baos;
            {
                WSSSecurityProperties securityProperties = new WSSSecurityProperties();
                List<WSSConstants.Action> actions = new ArrayList<>();
                actions.add(WSSConstants.ENCRYPTION);
                securityProperties.setActions(actions);
                securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
                securityProperties.setEncryptionUser("receiver");
                securityProperties.setEncryptionSymAlgorithm("http://www.w3.org/2009/xmlenc11#aes192-gcm");
                securityProperties.setEncryptionKeyTransportAlgorithm("http://www.w3.org/2009/xmlenc11#rsa-oaep");
                securityProperties.setEncryptionKeyTransportDigestAlgorithm("http://www.w3.org/2001/04/xmldsig-more#sha384");
                securityProperties.setEncryptionKeyTransportMGFAlgorithm("http://www.w3.org/2009/xmlenc11#mgf1sha384");

                InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
                baos = doOutboundSecurity(securityProperties, sourceDocument);

                Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
                NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
                assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

                XPathExpression xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2009/xmlenc11#rsa-oaep']");
                Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
                assertNotNull(node);

                xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod/dsig:DigestMethod[@Algorithm='http://www.w3.org/2001/04/xmldsig-more#sha384']");
                node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
                assertNotNull(node);

                xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod/xenc11:MGF[@Algorithm='http://www.w3.org/2009/xmlenc11#mgf1sha384']");
                node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
                assertNotNull(node);

                nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_DataReference.getNamespaceURI(), WSSConstants.TAG_xenc_DataReference.getLocalPart());
                assertEquals(nodeList.getLength(), 1);

                nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
                assertEquals(nodeList.getLength(), 1);

                xPathExpression = getXPath("/soap:Envelope/soap:Body/xenc:EncryptedData/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2009/xmlenc11#aes192-gcm']");
                node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
                assertNotNull(node);

                assertEquals(node.getParentNode().getParentNode().getLocalName(), "Body");
                NodeList childNodes = node.getParentNode().getParentNode().getChildNodes();
                for (int i = 0; i < childNodes.getLength(); i++) {
                    Node child = childNodes.item(i);
                    if (child.getNodeType() == Node.TEXT_NODE) {
                        assertEquals(child.getTextContent().trim(), "");
                    } else if (child.getNodeType() == Node.ELEMENT_NODE) {
                        assertEquals(child, nodeList.item(0));
                    } else {
                        fail("Unexpected Node encountered");
                    }
                }
            }
            //done encryption; now test decryption:
            {
                String action = WSHandlerConstants.ENCRYPT;
                doInboundSecurityWithWSS4J_1(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
            }
        } finally {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        }
    }

    @Test
    public void testKeyWrappingRSAOAEPAES192GCMSHA384MGF1sha1Inbound() throws Exception {

        assumeFalse(isIBMJdK);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.ENCRYPT;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.ENC_SYM_ALGO, "http://www.w3.org/2009/xmlenc11#aes192-gcm");
            properties.put(WSHandlerConstants.ENC_KEY_TRANSPORT, "http://www.w3.org/2009/xmlenc11#rsa-oaep");
            properties.put(WSHandlerConstants.ENC_DIGEST_ALGO, "http://www.w3.org/2001/04/xmldsig-more#sha384");
            properties.put(WSHandlerConstants.ENC_MGF_ALGO, "http://www.w3.org/2009/xmlenc11#mgf1sha1");

            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2009/xmlenc11#rsa-oaep']");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            assertNotNull(node);

            xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod/dsig:DigestMethod[@Algorithm='http://www.w3.org/2001/04/xmldsig-more#sha384']");
            node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            assertNotNull(node);

            xPathExpression = getXPath("/soap:Envelope/soap:Body/xenc:EncryptedData/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2009/xmlenc11#aes192-gcm']");
            node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            assertNotNull(node);

            Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }
        //test streaming decryption
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.addIgnoreBSPRule(BSPRule.R5620);
            securityProperties.addIgnoreBSPRule(BSPRule.R5621);

            Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 0);
        }
    }

    /**
     * rsa-oaep, Digest:SHA512, MGF:SHA1, PSource: Specified 8 bytes
     */

    @Test
    public void testKeyWrappingRSAOAEPAESGCM192SHA384MGF1SHA384PSourceOutbound() throws Exception {
        assumeFalse(isIBMJdK);
        try {
            Security.addProvider(new BouncyCastleProvider());
            ByteArrayOutputStream baos;
            {
                WSSSecurityProperties securityProperties = new WSSSecurityProperties();
                List<WSSConstants.Action> actions = new ArrayList<>();
                actions.add(WSSConstants.ENCRYPTION);
                securityProperties.setActions(actions);
                securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
                securityProperties.setEncryptionUser("receiver");
                securityProperties.setEncryptionSymAlgorithm("http://www.w3.org/2009/xmlenc11#aes192-gcm");
                securityProperties.setEncryptionKeyTransportAlgorithm("http://www.w3.org/2009/xmlenc11#rsa-oaep");
                securityProperties.setEncryptionKeyTransportDigestAlgorithm("http://www.w3.org/2001/04/xmldsig-more#sha384");
                securityProperties.setEncryptionKeyTransportMGFAlgorithm("http://www.w3.org/2009/xmlenc11#mgf1sha384");
                securityProperties.setEncryptionKeyTransportOAEPParams(XMLUtils.decode("ZHVtbXkxMjM=".getBytes(StandardCharsets.UTF_8)));

                InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
                baos = doOutboundSecurity(securityProperties, sourceDocument);

                Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
                NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
                assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

                XPathExpression xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2009/xmlenc11#rsa-oaep']");
                Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
                assertNotNull(node);

                xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod/xenc:OAEPparams");
                node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
                assertNotNull(node);

                xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod/dsig:DigestMethod[@Algorithm='http://www.w3.org/2001/04/xmldsig-more#sha384']");
                node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
                assertNotNull(node);

                xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod/xenc11:MGF[@Algorithm='http://www.w3.org/2009/xmlenc11#mgf1sha384']");
                node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
                assertNotNull(node);

                nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_DataReference.getNamespaceURI(), WSSConstants.TAG_xenc_DataReference.getLocalPart());
                assertEquals(nodeList.getLength(), 1);

                nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
                assertEquals(nodeList.getLength(), 1);

                xPathExpression = getXPath("/soap:Envelope/soap:Body/xenc:EncryptedData/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2009/xmlenc11#aes192-gcm']");
                node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
                assertNotNull(node);

                assertEquals(node.getParentNode().getParentNode().getLocalName(), "Body");
                NodeList childNodes = node.getParentNode().getParentNode().getChildNodes();
                for (int i = 0; i < childNodes.getLength(); i++) {
                    Node child = childNodes.item(i);
                    if (child.getNodeType() == Node.TEXT_NODE) {
                        assertEquals(child.getTextContent().trim(), "");
                    } else if (child.getNodeType() == Node.ELEMENT_NODE) {
                        assertEquals(child, nodeList.item(0));
                    } else {
                        fail("Unexpected Node encountered");
                    }
                }
            }
            //done encryption; now test decryption:
            {
                String action = WSHandlerConstants.ENCRYPT;
                doInboundSecurityWithWSS4J_1(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
            }
        } finally {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        }
    }

    @Test
    @org.junit.jupiter.api.Disabled //WSS4J does not support OAEPParams atm
    public void testKeyWrappingRSAOAEPAESGCM192SHA384MGF1SHA384PSourceInbound() throws Exception {
        assumeFalse(isIBMJdK);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.ENCRYPT;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.ENC_SYM_ALGO, "http://www.w3.org/2009/xmlenc11#aes192-gcm");
            properties.put(WSHandlerConstants.ENC_KEY_TRANSPORT, "http://www.w3.org/2009/xmlenc11#rsa-oaep");
            properties.put(WSHandlerConstants.ENC_DIGEST_ALGO, "http://www.w3.org/2001/04/xmldsig-more#sha384");
            properties.put(WSHandlerConstants.ENC_MGF_ALGO, "http://www.w3.org/2009/xmlenc11#mgf1sha384");
            //properties.put(WSHandlerConstants.ENC_OAEP_PARAMS, Base64.decode("ZHVtbXkxMjM=".getBytes(StandardCharsets.UTF_8)));

            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2009/xmlenc11#rsa-oaep']");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            assertNotNull(node);

            xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod/xenc:OAEPparams");
            node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            assertNotNull(node);

            xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod/dsig:DigestMethod[@Algorithm='http://www.w3.org/2001/04/xmldsig-more#sha384']");
            node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            assertNotNull(node);

            xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod/dsig:MGF[@Algorithm='http://www.w3.org/2009/xmlenc11#mgf1sha384']");
            node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            assertNotNull(node);

            xPathExpression = getXPath("/soap:Envelope/soap:Body/xenc:EncryptedData/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2009/xmlenc11#aes192-gcm']");
            node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            assertNotNull(node);

            Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }
        //test streaming decryption
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.addIgnoreBSPRule(BSPRule.R5620);
            securityProperties.addIgnoreBSPRule(BSPRule.R5621);

            Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 0);
        }
    }

    @Test
    public void testInboundRequiredAlgorithms() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.ENCRYPT;
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, new Properties());

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p']");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            assertNotNull(node);

            Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }
        //test streaming decryption
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.setEncryptionKeyTransportAlgorithm(WSSConstants.NS_XENC_RSAOAEPMGF1P);
            securityProperties.setEncryptionSymAlgorithm(WSSConstants.NS_XENC_AES128);
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), null);
        }
        // This should fail as we are requiring another key transport algorithm
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.setEncryptionKeyTransportAlgorithm(WSSConstants.NS_XENC_RSA15);
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            try {
                doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), null);
                fail("Failure expected on the wrong key transport algorithm");
            } catch (XMLStreamException e) {
                assertTrue(e.getCause() instanceof WSSecurityException);
            }
        }
        // This should fail as we are requiring another symmetric encryption algorithm
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.setEncryptionSymAlgorithm(WSSConstants.NS_XENC_TRIPLE_DES);
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            try {
                doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), null);
                fail("Failure expected on the wrong key transport algorithm");
            } catch (XMLStreamException e) {
                assertTrue(e.getCause() instanceof WSSecurityException);
            }
        }
    }

    @Test
    public void testEncDecryptionPropertiesOutbound() throws Exception {

        ByteArrayOutputStream baos;
        {
            Map<String, Object> config = new HashMap<>();
            config.put(ConfigurationConstants.ACTION, ConfigurationConstants.ENCRYPTION);
            config.put(ConfigurationConstants.ENCRYPTION_USER, "receiver");
            config.put(ConfigurationConstants.ENC_PROP_FILE, "transmitter-crypto.properties");

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            baos = doOutboundSecurity(config, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            XPathExpression xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p']");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_DataReference.getNamespaceURI(), WSSConstants.TAG_xenc_DataReference.getLocalPart());
            assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 1);

            xPathExpression = getXPath("/soap:Envelope/soap:Body/xenc:EncryptedData/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2001/04/xmlenc#aes256-cbc']");
            node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            assertNotNull(node);

            assertEquals(node.getParentNode().getParentNode().getLocalName(), "Body");
            NodeList childNodes = node.getParentNode().getParentNode().getChildNodes();
            for (int i = 0; i < childNodes.getLength(); i++) {
                Node child = childNodes.item(i);
                if (child.getNodeType() == Node.TEXT_NODE) {
                    assertEquals(child.getTextContent().trim(), "");
                } else if (child.getNodeType() == Node.ELEMENT_NODE) {
                    assertEquals(child, nodeList.item(0));
                } else {
                    fail("Unexpected Node encountered");
                }
            }
        }

        //done encryption; now test decryption:
        {
            String action = WSHandlerConstants.ENCRYPT;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testEncDecryptionPropertiesInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.ENCRYPT;
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, new Properties());

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p']");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            assertNotNull(node);

            Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }
        //test streaming decryption
        {
            Map<String, Object> config = new HashMap<>();
            config.put(ConfigurationConstants.ACTION, ConfigurationConstants.ENCRYPTION);
            config.put(ConfigurationConstants.DEC_PROP_FILE, "receiver-crypto.properties");
            config.put(ConfigurationConstants.PW_CALLBACK_REF, new CallbackHandlerImpl());

            WSSecurityEventConstants.Event[] expectedSecurityEvents = new WSSecurityEventConstants.Event[]{
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.X509Token,
                    WSSecurityEventConstants.ENCRYPTED_PART,
                    WSSecurityEventConstants.OPERATION,
            };
            final TestSecurityEventListener securityEventListener = new TestSecurityEventListener(expectedSecurityEvents);

            WSSSecurityProperties securityProperties = ConfigurationConverter.convert(config);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader outXmlStreamReader =
                wsSecIn.processInMessage(
                    xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())),
                    new ArrayList<SecurityEvent>(),
                    securityEventListener);
            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), outXmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 0);

            securityEventListener.compare();

            List<SecurityEvent> receivedSecurityEvents = securityEventListener.getReceivedSecurityEvents();
            for (int i = 0; i < receivedSecurityEvents.size(); i++) {
                SecurityEvent securityEvent = receivedSecurityEvents.get(i);
                if (securityEvent.getSecurityEventType() == WSSecurityEventConstants.OPERATION) {
                    OperationSecurityEvent operationSecurityEvent = (OperationSecurityEvent) securityEvent;
                    assertEquals(operationSecurityEvent.getOperation(), new QName("http://schemas.xmlsoap.org/wsdl/", "definitions"));
                } else if (securityEvent.getSecurityEventType() == WSSecurityEventConstants.ENCRYPTED_PART) {
                    EncryptedPartSecurityEvent encryptedPartSecurityEvent = (EncryptedPartSecurityEvent) securityEvent;
                    assertNotNull(encryptedPartSecurityEvent.getXmlSecEvent());
                    assertNotNull(encryptedPartSecurityEvent.getSecurityToken());
                    assertNotNull(encryptedPartSecurityEvent.getElementPath());
                    final QName expectedElementName = new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body");
                    assertEquals(encryptedPartSecurityEvent.getXmlSecEvent().asStartElement().getName(), expectedElementName);
                    assertEquals(encryptedPartSecurityEvent.getElementPath().size(), 2);
                    assertEquals(encryptedPartSecurityEvent.getElementPath().get(encryptedPartSecurityEvent.getElementPath().size() - 1), expectedElementName);
                }
            }

            EncryptedPartSecurityEvent encryptedPartSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.ENCRYPTED_PART);
            OperationSecurityEvent operationSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.OPERATION);
            String encryptedPartCorrelationID = encryptedPartSecurityEvent.getCorrelationID();
            String operationCorrelationID = operationSecurityEvent.getCorrelationID();

            List<SecurityEvent> operationSecurityEvents = new ArrayList<>();
            List<SecurityEvent> encryptedPartSecurityEvents = new ArrayList<>();

            List<SecurityEvent> securityEvents = securityEventListener.getReceivedSecurityEvents();
            for (int i = 0; i < securityEvents.size(); i++) {
                SecurityEvent securityEvent = securityEvents.get(i);
                if (securityEvent.getCorrelationID().equals(encryptedPartCorrelationID)) {
                    encryptedPartSecurityEvents.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(operationCorrelationID)) {
                    operationSecurityEvents.add(securityEvent);
                }
            }

            assertEquals(4, encryptedPartSecurityEvents.size());
            assertEquals(securityEventListener.getReceivedSecurityEvents().size(),
                    operationSecurityEvents.size() + encryptedPartSecurityEvents.size());
        }
    }

    @Test
    public void testElementoEncryptNotFound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.ENCRYPTION);
            securityProperties.setActions(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setTokenUser("transmitter");
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.addEncryptionPart(
                    new SecurePart(new QName(WSSConstants.NS_WSSE10, "UsernameToken"), SecurePart.Modifier.Element)
            );
            securityProperties.addEncryptionPart(
                    new SecurePart(new QName(WSSConstants.NS_SOAP11, "Body"), SecurePart.Modifier.Content)
            );

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));

            try {
                XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
                xmlStreamWriter.close();
                fail("Exception expected");
            } catch (XMLStreamException e) {
                assertTrue(e.getCause() instanceof XMLSecurityException);
                assertEquals("Part to encrypt not found: {http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}UsernameToken", e.getCause().getMessage());
            }
        }
    }

    @Test
    public void testEncryptedDataSecurityHeaderWithoutReferenceInbound() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

            Document doc = documentBuilderFactory.newDocumentBuilder().parse(sourceDocument);

            WSSecHeader secHeader = new WSSecHeader(doc);
            secHeader.insertSecurityHeader();
            Element securityHeaderElement = secHeader.getSecurityHeaderElement();
            securityHeaderElement.appendChild(doc.getElementsByTagNameNS("http://schemas.xmlsoap.org/wsdl/", "definitions").item(0));

            WSSecEncrypt builder = new WSSecEncrypt(secHeader);
            builder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
            builder.setUserInfo("receiver");
            Crypto crypto = CryptoFactory.getInstance("transmitter-crypto.properties");

            KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.AES_128);
            SecretKey symmetricKey = keyGen.generateKey();
            builder.prepare(crypto, symmetricKey);

            WSEncryptionPart encP = new WSEncryptionPart("definitions", "http://schemas.xmlsoap.org/wsdl/", "Element");
            List<WSEncryptionPart> encryptionParts = new ArrayList<>();
            encryptionParts.add(encP);
            Element ref = builder.encryptForRef(null, encryptionParts, symmetricKey);
            ref.removeChild(ref.getElementsByTagNameNS("http://www.w3.org/2001/04/xmlenc#", "DataReference").item(0));
            builder.addExternalRefElement(ref);
            builder.prependToHeader();

            Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(doc), new StreamResult(baos));
        }

        //done encryption; now test decryption:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            //no encrypted content
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 0);
        }
    }

    @Test
    public void testEncryptedDataSecurityHeaderPrependedReferenceInbound() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

            Document doc = documentBuilderFactory.newDocumentBuilder().parse(sourceDocument);

            WSSecHeader secHeader = new WSSecHeader(doc);
            secHeader.insertSecurityHeader();
            Element securityHeaderElement = secHeader.getSecurityHeaderElement();
            securityHeaderElement.appendChild(doc.getElementsByTagNameNS("http://schemas.xmlsoap.org/wsdl/", "definitions").item(0));

            WSSecEncrypt builder = new WSSecEncrypt(secHeader);
            builder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
            builder.setUserInfo("receiver");
            Crypto crypto = CryptoFactory.getInstance("transmitter-crypto.properties");

            KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.AES_128);
            SecretKey symmetricKey = keyGen.generateKey();
            builder.prepare(crypto, symmetricKey);

            WSEncryptionPart encP = new WSEncryptionPart("definitions", "http://schemas.xmlsoap.org/wsdl/", "Element");
            List<WSEncryptionPart> encryptionParts = new ArrayList<>();
            encryptionParts.add(encP);
            Element ref = builder.encryptForRef(null, encryptionParts, symmetricKey);
            builder.addExternalRefElement(ref);
            builder.prependToHeader();

            Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(doc), new StreamResult(baos));
        }

        //done encryption; now test decryption:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            //no encrypted content
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 0);
        }
    }

    @Test
    public void testEncryptedDataSecurityHeaderAppendedReferenceInbound() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

            Document doc = documentBuilderFactory.newDocumentBuilder().parse(sourceDocument);

            WSSecHeader secHeader = new WSSecHeader(doc);
            secHeader.insertSecurityHeader();
            Element securityHeaderElement = secHeader.getSecurityHeaderElement();
            securityHeaderElement.appendChild(doc.getElementsByTagNameNS("http://schemas.xmlsoap.org/wsdl/", "definitions").item(0));

            WSSecEncrypt builder = new WSSecEncrypt(secHeader);
            builder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
            builder.setUserInfo("receiver");
            Crypto crypto = CryptoFactory.getInstance("transmitter-crypto.properties");

            KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.AES_128);
            SecretKey symmetricKey = keyGen.generateKey();
            builder.prepare(crypto, symmetricKey);

            WSEncryptionPart encP = new WSEncryptionPart("definitions", "http://schemas.xmlsoap.org/wsdl/", "Element");
            List<WSEncryptionPart> encryptionParts = new ArrayList<>();
            encryptionParts.add(encP);
            Element ref = builder.encryptForRef(null, encryptionParts, symmetricKey);
            builder.prependToHeader();
            //builder.addExternalRefElement(ref, secHeader);
            securityHeaderElement.appendChild(ref);

            Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(doc), new StreamResult(baos));
        }

        //done encryption; now test decryption:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            //no encrypted content
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 0);
        }
    }
}
