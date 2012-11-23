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
package org.apache.ws.security.stax.test;

import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorOutputStream;
import org.apache.commons.compress.compressors.xz.XZCompressorInputStream;
import org.apache.commons.compress.compressors.xz.XZCompressorOutputStream;
import org.apache.ws.security.common.bsp.BSPRule;
import org.apache.ws.security.dom.handler.WSHandlerConstants;
import org.apache.ws.security.stax.WSSec;
import org.apache.ws.security.stax.ext.WSSConstants;
import org.apache.ws.security.stax.ext.WSSSecurityProperties;
import org.apache.ws.security.stax.securityEvent.*;
import org.apache.xml.security.stax.config.Init;
import org.apache.xml.security.stax.config.TransformerAlgorithmMapper;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.securityEvent.ContentEncryptedElementSecurityEvent;
import org.apache.xml.security.stax.securityEvent.EncryptedElementSecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEventConstants;
import org.apache.xml.security.utils.Base64;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.namespace.QName;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class EncDecryptionTest extends AbstractTestBase {

    @Test
    public void testEncDecryptionDefaultConfigurationOutbound() throws Exception {

        ByteArrayOutputStream baos;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.ENCRYPT};
            securityProperties.setOutAction(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p']");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_DataReference.getNamespaceURI(), WSSConstants.TAG_xenc_DataReference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            xPathExpression = getXPath("/env:Envelope/env:Body/xenc:EncryptedData/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2001/04/xmlenc#aes256-cbc']");
            node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            Assert.assertEquals(node.getParentNode().getParentNode().getLocalName(), "Body");
            NodeList childNodes = node.getParentNode().getParentNode().getChildNodes();
            for (int i = 0; i < childNodes.getLength(); i++) {
                Node child = childNodes.item(i);
                if (child.getNodeType() == Node.TEXT_NODE) {
                    Assert.assertEquals(child.getTextContent().trim(), "");
                } else if (child.getNodeType() == Node.ELEMENT_NODE) {
                    Assert.assertEquals(child, nodeList.item(0));
                } else {
                    Assert.fail("Unexpected Node encountered");
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
    public void testEncDecryptionDefaultConfigurationInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.ENCRYPT;
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, new Properties());

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p']");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }
        //test streaming decryption
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            WSSecurityEventConstants.Event[] expectedSecurityEvents = new WSSecurityEventConstants.Event[]{
                    WSSecurityEventConstants.X509Token,
                    WSSecurityEventConstants.EncryptedPart,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.Operation,
            };
            final TestSecurityEventListener securityEventListener = new TestSecurityEventListener(expectedSecurityEvents);

            Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), securityEventListener);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);

            securityEventListener.compare();

            List<SecurityEvent> receivedSecurityEvents = securityEventListener.getReceivedSecurityEvents();
            for (int i = 0; i < receivedSecurityEvents.size(); i++) {
                SecurityEvent securityEvent = receivedSecurityEvents.get(i);
                if (securityEvent.getSecurityEventType() == WSSecurityEventConstants.Operation) {
                    OperationSecurityEvent operationSecurityEvent = (OperationSecurityEvent) securityEvent;
                    Assert.assertEquals(operationSecurityEvent.getOperation(), new QName("http://schemas.xmlsoap.org/wsdl/", "definitions"));
                } else if (securityEvent.getSecurityEventType() == WSSecurityEventConstants.EncryptedPart) {
                    EncryptedPartSecurityEvent encryptedPartSecurityEvent = (EncryptedPartSecurityEvent) securityEvent;
                    Assert.assertNotNull(encryptedPartSecurityEvent.getXmlSecEvent());
                    Assert.assertNotNull(encryptedPartSecurityEvent.getSecurityToken());
                    Assert.assertNotNull(encryptedPartSecurityEvent.getElementPath());
                    final QName expectedElementName = new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body");
                    Assert.assertEquals(encryptedPartSecurityEvent.getXmlSecEvent().asStartElement().getName(), expectedElementName);
                    Assert.assertEquals(encryptedPartSecurityEvent.getElementPath().size(), 2);
                    Assert.assertEquals(encryptedPartSecurityEvent.getElementPath().get(encryptedPartSecurityEvent.getElementPath().size() - 1), expectedElementName);
                }
            }

            EncryptedPartSecurityEvent encryptedPartSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.EncryptedPart);
            OperationSecurityEvent operationSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.Operation);
            String encryptedPartCorrelationID = encryptedPartSecurityEvent.getCorrelationID();
            String operationCorrelationID = operationSecurityEvent.getCorrelationID();

            List<SecurityEvent> operationSecurityEvents = new ArrayList<SecurityEvent>();
            List<SecurityEvent> encryptedPartSecurityEvents = new ArrayList<SecurityEvent>();

            List<SecurityEvent> securityEvents = securityEventListener.getReceivedSecurityEvents();
            for (int i = 0; i < securityEvents.size(); i++) {
                SecurityEvent securityEvent = securityEvents.get(i);
                if (securityEvent.getCorrelationID().equals(encryptedPartCorrelationID)) {
                    encryptedPartSecurityEvents.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(operationCorrelationID)) {
                    operationSecurityEvents.add(securityEvent);
                }
            }

            org.junit.Assert.assertEquals(4, encryptedPartSecurityEvents.size());
            org.junit.Assert.assertEquals(securityEventListener.getReceivedSecurityEvents().size(),
                    operationSecurityEvents.size() + encryptedPartSecurityEvents.size());
        }
    }

    @Test
    public void testEncDecryptionPartsContentOutbound() throws Exception {

        ByteArrayOutputStream baos;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.ENCRYPT};
            securityProperties.setOutAction(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.addEncryptionPart(new SecurePart(new QName("http://www.w3.org/1999/XMLSchema", "complexType"), SecurePart.Modifier.Content));

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_DataReference.getNamespaceURI(), WSSConstants.TAG_xenc_DataReference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 25);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 25);

            for (int i = 0; i < nodeList.getLength(); i++) {
                Assert.assertEquals(nodeList.item(i).getParentNode().getLocalName(), "complexType");
                Assert.assertEquals(nodeList.item(i).getParentNode().getNamespaceURI(), "http://www.w3.org/1999/XMLSchema");
                NodeList childNodes = nodeList.item(i).getParentNode().getChildNodes();
                for (int j = 0; j < childNodes.getLength(); j++) {
                    Node child = childNodes.item(j);
                    if (child.getNodeType() == Node.TEXT_NODE) {
                        Assert.assertEquals(child.getTextContent().trim(), "");
                    } else if (child.getNodeType() == Node.ELEMENT_NODE) {
                        Assert.assertEquals(child, nodeList.item(i));
                    } else {
                        Assert.fail("Unexpected Node encountered");
                    }
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
    public void testEncDecryptionPartsContentInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.ENCRYPT;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.ENCRYPTION_PARTS, "{Content}{http://www.w3.org/1999/XMLSchema}simpleType;");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }
        //test streaming decryption
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            WSSecurityEventConstants.Event[] expectedSecurityEvents = new WSSecurityEventConstants.Event[]{
                    WSSecurityEventConstants.X509Token,
                    WSSecurityEventConstants.Operation,
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
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);

            securityEventListener.compare();

            List<SecurityEvent> receivedSecurityEvents = securityEventListener.getReceivedSecurityEvents();
            for (int i = 0; i < receivedSecurityEvents.size(); i++) {
                SecurityEvent securityEvent = receivedSecurityEvents.get(i);
                if (securityEvent.getSecurityEventType() == WSSecurityEventConstants.Operation) {
                    OperationSecurityEvent operationSecurityEvent = (OperationSecurityEvent) securityEvent;
                    Assert.assertEquals(operationSecurityEvent.getOperation(), new QName("http://schemas.xmlsoap.org/wsdl/", "definitions"));
                } else if (securityEvent.getSecurityEventType() == WSSecurityEventConstants.ContentEncrypted) {
                    ContentEncryptedElementSecurityEvent contentEncryptedElementSecurityEvent = (ContentEncryptedElementSecurityEvent) securityEvent;
                    Assert.assertNotNull(contentEncryptedElementSecurityEvent.getXmlSecEvent());
                    Assert.assertNotNull(contentEncryptedElementSecurityEvent.getSecurityToken());
                    Assert.assertNotNull(contentEncryptedElementSecurityEvent.getElementPath());
                    final QName expectedElementName = new QName("http://www.w3.org/1999/XMLSchema", "simpleType");
                    Assert.assertEquals(contentEncryptedElementSecurityEvent.getXmlSecEvent().asStartElement().getName(), expectedElementName);
                    Assert.assertEquals(contentEncryptedElementSecurityEvent.getElementPath().size(), 6);
                    Assert.assertEquals(contentEncryptedElementSecurityEvent.getElementPath().get(contentEncryptedElementSecurityEvent.getElementPath().size() - 1), expectedElementName);
                }
            }

            List<ContentEncryptedElementSecurityEvent> contentEncryptedElementSecurityEventList = securityEventListener.getSecurityEvents(SecurityEventConstants.ContentEncrypted);
            OperationSecurityEvent operationSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.Operation);
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

            List<SecurityEvent> operationSecurityEvents = new ArrayList<SecurityEvent>();
            List<SecurityEvent> encryptedPartSecurityEvents1 = new ArrayList<SecurityEvent>();
            List<SecurityEvent> encryptedPartSecurityEvents2 = new ArrayList<SecurityEvent>();
            List<SecurityEvent> encryptedPartSecurityEvents3 = new ArrayList<SecurityEvent>();
            List<SecurityEvent> encryptedPartSecurityEvents4 = new ArrayList<SecurityEvent>();
            List<SecurityEvent> encryptedPartSecurityEvents5 = new ArrayList<SecurityEvent>();
            List<SecurityEvent> encryptedPartSecurityEvents6 = new ArrayList<SecurityEvent>();
            List<SecurityEvent> encryptedPartSecurityEvents7 = new ArrayList<SecurityEvent>();
            List<SecurityEvent> encryptedPartSecurityEvents8 = new ArrayList<SecurityEvent>();
            List<SecurityEvent> encryptedPartSecurityEvents9 = new ArrayList<SecurityEvent>();
            List<SecurityEvent> encryptedPartSecurityEvents10 = new ArrayList<SecurityEvent>();
            List<SecurityEvent> encryptedPartSecurityEvents11 = new ArrayList<SecurityEvent>();
            List<SecurityEvent> encryptedPartSecurityEvents12 = new ArrayList<SecurityEvent>();
            List<SecurityEvent> encryptedPartSecurityEvents13 = new ArrayList<SecurityEvent>();
            List<SecurityEvent> encryptedPartSecurityEvents14 = new ArrayList<SecurityEvent>();
            List<SecurityEvent> encryptedPartSecurityEvents15 = new ArrayList<SecurityEvent>();
            List<SecurityEvent> encryptedPartSecurityEvents16 = new ArrayList<SecurityEvent>();
            List<SecurityEvent> encryptedPartSecurityEvents17 = new ArrayList<SecurityEvent>();

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

            org.junit.Assert.assertEquals(4, encryptedPartSecurityEvents1.size());
            org.junit.Assert.assertEquals(3, encryptedPartSecurityEvents2.size());
            org.junit.Assert.assertEquals(3, encryptedPartSecurityEvents3.size());
            org.junit.Assert.assertEquals(3, encryptedPartSecurityEvents4.size());
            org.junit.Assert.assertEquals(3, encryptedPartSecurityEvents5.size());
            org.junit.Assert.assertEquals(3, encryptedPartSecurityEvents6.size());
            org.junit.Assert.assertEquals(3, encryptedPartSecurityEvents7.size());
            org.junit.Assert.assertEquals(3, encryptedPartSecurityEvents8.size());
            org.junit.Assert.assertEquals(3, encryptedPartSecurityEvents9.size());
            org.junit.Assert.assertEquals(3, encryptedPartSecurityEvents10.size());
            org.junit.Assert.assertEquals(3, encryptedPartSecurityEvents11.size());
            org.junit.Assert.assertEquals(3, encryptedPartSecurityEvents12.size());
            org.junit.Assert.assertEquals(3, encryptedPartSecurityEvents13.size());
            org.junit.Assert.assertEquals(3, encryptedPartSecurityEvents14.size());
            org.junit.Assert.assertEquals(3, encryptedPartSecurityEvents15.size());
            org.junit.Assert.assertEquals(3, encryptedPartSecurityEvents16.size());
            org.junit.Assert.assertEquals(3, encryptedPartSecurityEvents17.size());
            org.junit.Assert.assertEquals(securityEventListener.getReceivedSecurityEvents().size(),
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
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.ENCRYPT};
            securityProperties.setOutAction(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.addEncryptionPart(new SecurePart(new QName("http://www.w3.org/1999/XMLSchema", "complexType"), SecurePart.Modifier.Element));

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 25);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_DataReference.getNamespaceURI(), WSSConstants.TAG_xenc_DataReference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 25);

            nodeList = document.getElementsByTagNameNS("http://www.w3.org/1999/XMLSchema", "complexType");
            Assert.assertEquals(nodeList.getLength(), 0);
        }

        //done encryption; now test decryption:
        {
            String action = WSHandlerConstants.ENCRYPT;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testEncDecryptionPartsHeaderOutbound() throws Exception {

        ByteArrayOutputStream baos;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.ENCRYPT};
            securityProperties.setOutAction(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.addEncryptionPart(new SecurePart(new QName("http://www.w3.org/1999/XMLSchema", "complexType"), SecurePart.Modifier.Element));
            securityProperties.addEncryptionPart(new SecurePart(new QName("http://www.example.com", "testEncryptedHeader"), SecurePart.Modifier.Element));

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-encryptedHeader.xml");

            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 27);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_DataReference.getNamespaceURI(), WSSConstants.TAG_xenc_DataReference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 26);

            nodeList = document.getElementsByTagNameNS("http://www.w3.org/1999/XMLSchema", "complexType");
            Assert.assertEquals(nodeList.getLength(), 0);
        }

        //done encryption; now test decryption:
        {
            String action = WSHandlerConstants.ENCRYPT;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testEncDecryptionPartsElementInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.ENCRYPT;
            Properties properties = new Properties();

            properties.setProperty(WSHandlerConstants.ENCRYPTION_PARTS, "{Element}{http://www.w3.org/1999/XMLSchema}simpleType;");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done encryption; now test decryption:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new org.apache.ws.security.stax.test.CallbackHandlerImpl());

            WSSecurityEventConstants.Event[] expectedSecurityEvents = new WSSecurityEventConstants.Event[]{
                    WSSecurityEventConstants.X509Token,
                    WSSecurityEventConstants.Operation,
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
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);

            securityEventListener.compare();

            List<SecurityEvent> receivedSecurityEvents = securityEventListener.getReceivedSecurityEvents();
            for (int i = 0; i < receivedSecurityEvents.size(); i++) {
                SecurityEvent securityEvent = receivedSecurityEvents.get(i);
                if (securityEvent.getSecurityEventType() == WSSecurityEventConstants.Operation) {
                    OperationSecurityEvent operationSecurityEvent = (OperationSecurityEvent) securityEvent;
                    Assert.assertEquals(operationSecurityEvent.getOperation(), new QName("http://schemas.xmlsoap.org/wsdl/", "definitions"));
                } else if (securityEvent.getSecurityEventType() == WSSecurityEventConstants.EncryptedElement) {
                    EncryptedElementSecurityEvent encryptedElementSecurityEvent = (EncryptedElementSecurityEvent) securityEvent;
                    Assert.assertNotNull(encryptedElementSecurityEvent.getXmlSecEvent());
                    Assert.assertNotNull(encryptedElementSecurityEvent.getSecurityToken());
                    Assert.assertNotNull(encryptedElementSecurityEvent.getElementPath());
                    final QName expectedElementName = new QName("http://www.w3.org/1999/XMLSchema", "simpleType");
                    Assert.assertEquals(encryptedElementSecurityEvent.getXmlSecEvent().asStartElement().getName(), expectedElementName);
                    Assert.assertEquals(encryptedElementSecurityEvent.getElementPath().size(), 6);
                    Assert.assertEquals(encryptedElementSecurityEvent.getElementPath().get(encryptedElementSecurityEvent.getElementPath().size() - 1), expectedElementName);
                }
            }
        }
    }

    @Test
    public void testEncDecryptionPartsHeaderInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-encryptedHeader.xml");
            String action = WSHandlerConstants.ENCRYPT;
            Properties properties = new Properties();

            properties.setProperty(WSHandlerConstants.ENCRYPTION_PARTS, "{Header}{http://www.example.com}testEncryptedHeader;");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done encryption; now test decryption:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new org.apache.ws.security.stax.test.CallbackHandlerImpl());

            WSSecurityEventConstants.Event[] expectedSecurityEvents = new WSSecurityEventConstants.Event[]{
                    WSSecurityEventConstants.X509Token,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.EncryptedPart,
                    WSSecurityEventConstants.Operation,
            };
            final TestSecurityEventListener securityEventListener = new TestSecurityEventListener(expectedSecurityEvents);

            Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), securityEventListener);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_wsse11_EncryptedHeader.getNamespaceURI(), WSSConstants.TAG_wsse11_EncryptedHeader.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            securityEventListener.compare();

            List<SecurityEvent> receivedSecurityEvents = securityEventListener.getReceivedSecurityEvents();
            for (int i = 0; i < receivedSecurityEvents.size(); i++) {
                SecurityEvent securityEvent = receivedSecurityEvents.get(i);
                if (securityEvent.getSecurityEventType() == WSSecurityEventConstants.Operation) {
                    OperationSecurityEvent operationSecurityEvent = (OperationSecurityEvent) securityEvent;
                    Assert.assertEquals(operationSecurityEvent.getOperation(), new QName("http://schemas.xmlsoap.org/wsdl/", "definitions"));
                } else if (securityEvent.getSecurityEventType() == WSSecurityEventConstants.EncryptedPart) {
                    EncryptedPartSecurityEvent encryptedPartSecurityEvent = (EncryptedPartSecurityEvent) securityEvent;
                    Assert.assertNotNull(encryptedPartSecurityEvent.getXmlSecEvent());
                    Assert.assertNotNull(encryptedPartSecurityEvent.getSecurityToken());
                    Assert.assertNotNull(encryptedPartSecurityEvent.getElementPath());
                    final QName expectedElementName = new QName("http://www.example.com", "testEncryptedHeader");
                    Assert.assertEquals(encryptedPartSecurityEvent.getXmlSecEvent().asStartElement().getName(), expectedElementName);
                    Assert.assertEquals(encryptedPartSecurityEvent.getElementPath().size(), 3);
                    Assert.assertEquals(encryptedPartSecurityEvent.getElementPath().get(encryptedPartSecurityEvent.getElementPath().size() - 1), expectedElementName);
                }
            }

            EncryptedPartSecurityEvent encryptedPartSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.EncryptedPart);
            OperationSecurityEvent operationSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.Operation);
            String encryptedPartCorrelationID = encryptedPartSecurityEvent.getCorrelationID();
            String operationCorrelationID = operationSecurityEvent.getCorrelationID();

            List<SecurityEvent> operationSecurityEvents = new ArrayList<SecurityEvent>();
            List<SecurityEvent> encryptedPartSecurityEvents = new ArrayList<SecurityEvent>();

            List<SecurityEvent> securityEvents = securityEventListener.getReceivedSecurityEvents();
            for (int i = 0; i < securityEvents.size(); i++) {
                SecurityEvent securityEvent = securityEvents.get(i);
                if (securityEvent.getCorrelationID().equals(encryptedPartCorrelationID)) {
                    encryptedPartSecurityEvents.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(operationCorrelationID)) {
                    operationSecurityEvents.add(securityEvent);
                }
            }

            org.junit.Assert.assertEquals(4, encryptedPartSecurityEvents.size());
            org.junit.Assert.assertEquals(securityEventListener.getReceivedSecurityEvents().size(),
                    operationSecurityEvents.size() + encryptedPartSecurityEvents.size());
        }
    }

    @Test
    public void testEncDecryptionUseThisCert() throws Exception {

        ByteArrayOutputStream baos;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.ENCRYPT};
            securityProperties.setOutAction(actions);

            KeyStore keyStore = KeyStore.getInstance("jks");
            keyStore.load(this.getClass().getClassLoader().getResourceAsStream("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUseThisCertificate((X509Certificate) keyStore.getCertificate("receiver"));

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_DataReference.getNamespaceURI(), WSSConstants.TAG_xenc_DataReference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), "Body");
            NodeList childNodes = nodeList.item(0).getParentNode().getChildNodes();
            for (int i = 0; i < childNodes.getLength(); i++) {
                Node child = childNodes.item(i);
                if (child.getNodeType() == Node.TEXT_NODE) {
                    Assert.assertEquals(child.getTextContent().trim(), "");
                } else if (child.getNodeType() == Node.ELEMENT_NODE) {
                    Assert.assertEquals(child, nodeList.item(0));
                } else {
                    Assert.fail("Unexpected Node encountered");
                }
            }
        }

        //done encryption; now test decryption:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new org.apache.ws.security.stax.test.CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, new ByteArrayInputStream(baos.toByteArray()));

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }
    }

    @Test
    public void testEncDecryptionKeyIdentifierIssuerSerialOutbound() throws Exception {

        ByteArrayOutputStream baos;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.ENCRYPT};
            securityProperties.setOutAction(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionKeyIdentifierType(WSSConstants.WSSKeyIdentifierType.ISSUER_SERIAL);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/dsig:KeyInfo/wsse:SecurityTokenReference/dsig:X509Data/dsig:X509IssuerSerial/dsig:X509SerialNumber");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_DataReference.getNamespaceURI(), WSSConstants.TAG_xenc_DataReference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
        }

        //done encryption; now test decryption:
        {
            String action = WSHandlerConstants.ENCRYPT;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testEncDecryptionKeyIdentifierIssuerSerialInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.ENCRYPT;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.ENC_KEY_ID, "IssuerSerial");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/dsig:KeyInfo/wsse:SecurityTokenReference/dsig:X509Data/dsig:X509IssuerSerial/dsig:X509SerialNumber");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done encryption; now test decryption:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new org.apache.ws.security.stax.test.CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }
    }

    @Test
    public void testEncDecryptionKeyIdentifierBinarySecurityTokenDirectReferenceOutbound() throws Exception {

        ByteArrayOutputStream baos;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.ENCRYPT};
            securityProperties.setOutAction(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionKeyIdentifierType(WSSConstants.WSSKeyIdentifierType.SECURITY_TOKEN_DIRECT_REFERENCE);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/wsse:BinarySecurityToken");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_DataReference.getNamespaceURI(), WSSConstants.TAG_xenc_DataReference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
        }

        //done encryption; now test decryption:
        {
            String action = WSHandlerConstants.ENCRYPT;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testEncDecryptionKeyIdentifierBinarySecurityTokenDirectReferenceInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.ENCRYPT;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.ENC_KEY_ID, "DirectReference");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/wsse:BinarySecurityToken");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done encryption; now test decryption:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new org.apache.ws.security.stax.test.CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
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
     * String action = WSHandlerConstants.ENCRYPT;
     * Properties properties = new Properties();
     * properties.setProperty(WSHandlerConstants.ENC_KEY_ID, "DirectReference");
     * Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);
     * <p/>
     * //some test that we can really sure we get what we want from WSS4J
     * XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/wsse:BinarySecurityToken");
     * Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
     * Assert.assertNotNull(node);
     * Element parentElement = (Element) node.getParentNode();
     * parentElement.removeChild(node);
     * parentElement.appendChild(node);
     * <p/>
     * javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
     * transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
     * }
     * <p/>
     * //done encryption; now test decryption:
     * {
     * WSSSecurityProperties securityProperties = new WSSSecurityProperties();
     * securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
     * securityProperties.setCallbackHandler(new org.apache.ws.security.test.CallbackHandlerImpl());
     * Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));
     * <p/>
     * //header element must still be there
     * NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
     * Assert.assertEquals(nodeList.getLength(), 1);
     * Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());
     * <p/>
     * //no encrypted content
     * nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
     * Assert.assertEquals(nodeList.getLength(), 0);
     * }
     * }
     */

/*  Not spec conform and therefore not supported!:
    @Test
    public void testEncDecryptionKeyIdentifierBinarySecurityTokenEmbedded() throws Exception {

        ByteArrayOutputStream baos;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.ENCRYPT};
            securityProperties.setOutAction(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionKeyIdentifierType(WSSConstants.WSSKeyIdentifierType.BST_EMBEDDED);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:Reference/wsse:BinarySecurityToken");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_DataReference.getNamespaceURI(), WSSConstants.TAG_xenc_DataReference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
        }

        //done encryption; now test decryption:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new org.apache.ws.security.stax.test.CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, new ByteArrayInputStream(baos.toByteArray()));

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }
    }*/

    @Test
    public void testEncDecryptionKeyIdentifierX509KeyOutbound() throws Exception {

        ByteArrayOutputStream baos;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.ENCRYPT};
            securityProperties.setOutAction(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionKeyIdentifierType(WSSConstants.WSSKeyIdentifierType.X509_KEY_IDENTIFIER);
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:KeyIdentifier[@ValueType='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3']");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_DataReference.getNamespaceURI(), WSSConstants.TAG_xenc_DataReference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
        }

        //done encryption; now test decryption:
        {
            String action = WSHandlerConstants.ENCRYPT;
            Properties properties = new Properties();
            doInboundSecurityWithWSS4J_1(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action, properties, false);
        }
    }

    @Test
    public void testEncDecryptionKeyIdentifierX509KeyInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.ENCRYPT;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.ENC_KEY_ID, "X509KeyIdentifier");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:KeyIdentifier[@ValueType='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3']");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done encryption; now test decryption:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new org.apache.ws.security.stax.test.CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }
    }

    @Test
    public void testEncDecryptionKeyIdentifierSubjectKeyOutbound() throws Exception {

        ByteArrayOutputStream baos;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.ENCRYPT};
            securityProperties.setOutAction(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionKeyIdentifierType(WSSConstants.WSSKeyIdentifierType.SKI_KEY_IDENTIFIER);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:KeyIdentifier[@ValueType='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier']");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_DataReference.getNamespaceURI(), WSSConstants.TAG_xenc_DataReference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
        }

        //done encryption; now test decryption:
        {
            String action = WSHandlerConstants.ENCRYPT;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testEncDecryptionKeyIdentifierSubjectKeyInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.ENCRYPT;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.ENC_KEY_ID, "SKIKeyIdentifier");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:KeyIdentifier[@ValueType='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier']");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done encryption; now test decryption:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new org.apache.ws.security.stax.test.CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }
    }

    @Test
    public void testEncDecryptionKeyIdentifierThumbprintOutbound() throws Exception {

        ByteArrayOutputStream baos;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.ENCRYPT};
            securityProperties.setOutAction(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionKeyIdentifierType(WSSConstants.WSSKeyIdentifierType.THUMBPRINT_IDENTIFIER);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:KeyIdentifier[@ValueType='http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1']");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_DataReference.getNamespaceURI(), WSSConstants.TAG_xenc_DataReference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
        }

        //done encryption; now test decryption:
        {
            String action = WSHandlerConstants.ENCRYPT;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testEncDecryptionKeyIdentifierThumbprintInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.ENCRYPT;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.ENC_KEY_ID, "Thumbprint");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:KeyIdentifier[@ValueType='http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1']");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done encryption; now test decryption:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new org.apache.ws.security.stax.test.CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }
    }

    @Test
    public void testDecryptionReferenceListOutsideEncryptedKey() throws Exception {

        ByteArrayOutputStream baos;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.ENCRYPT};
            securityProperties.setOutAction(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionKeyIdentifierType(WSSConstants.WSSKeyIdentifierType.ISSUER_SERIAL);

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/dsig:KeyInfo/wsse:SecurityTokenReference/dsig:X509Data/dsig:X509IssuerSerial/dsig:X509SerialNumber");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_DataReference.getNamespaceURI(), WSSConstants.TAG_xenc_DataReference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

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
            securityProperties.setCallbackHandler(new org.apache.ws.security.stax.test.CallbackHandlerImpl());
            Document document = doInboundSecurity(securityProperties, new ByteArrayInputStream(baos.toByteArray()));

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }
    }

    @Test
    public void testEncDecryptionSuperEncryptionInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.ENCRYPT;
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, new Properties());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));

            securedDocument = doOutboundSecurityWithWSS4J(new ByteArrayInputStream(baos.toByteArray()), action, new Properties());

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p']");
            NodeList nodeList = (NodeList) xPathExpression.evaluate(securedDocument, XPathConstants.NODESET);
            Assert.assertEquals(nodeList.getLength(), 2);

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
            Assert.assertEquals(nodeList.getLength(), 2);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }
    }

    @Test
    public void testCompressedEncDecryption() throws Exception {

        Init.init(WSSec.class.getClassLoader().getResource("wss/wss-config.xml").toURI());
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
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.ENCRYPT};
            securityProperties.setOutAction(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionCompressionAlgorithm("http://www.apache.org/2012/04/xmlsec/gzip");

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p']");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_DataReference.getNamespaceURI(), WSSConstants.TAG_xenc_DataReference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            xPathExpression = getXPath("/env:Envelope/env:Body/xenc:EncryptedData/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2001/04/xmlenc#aes256-cbc']");
            node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            Assert.assertEquals(node.getParentNode().getParentNode().getLocalName(), "Body");
            NodeList childNodes = node.getParentNode().getParentNode().getChildNodes();
            for (int i = 0; i < childNodes.getLength(); i++) {
                Node child = childNodes.item(i);
                if (child.getNodeType() == Node.TEXT_NODE) {
                    Assert.assertEquals(child.getTextContent().trim(), "");
                } else if (child.getNodeType() == Node.ELEMENT_NODE) {
                    Assert.assertEquals(child, nodeList.item(0));
                } else {
                    Assert.fail("Unexpected Node encountered");
                }
            }
        }

        //done encryption; now test decryption:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            WSSecurityEventConstants.Event[] expectedSecurityEvents = new WSSecurityEventConstants.Event[]{
                    WSSecurityEventConstants.X509Token,
                    WSSecurityEventConstants.EncryptedPart,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.Operation,
            };
            final TestSecurityEventListener securityEventListener = new TestSecurityEventListener(expectedSecurityEvents);

            Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), securityEventListener);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);

            securityEventListener.compare();

            List<SecurityEvent> receivedSecurityEvents = securityEventListener.getReceivedSecurityEvents();
            for (int i = 0; i < receivedSecurityEvents.size(); i++) {
                SecurityEvent securityEvent = receivedSecurityEvents.get(i);
                if (securityEvent.getSecurityEventType() == WSSecurityEventConstants.Operation) {
                    OperationSecurityEvent operationSecurityEvent = (OperationSecurityEvent) securityEvent;
                    Assert.assertEquals(operationSecurityEvent.getOperation(), new QName("http://schemas.xmlsoap.org/wsdl/", "definitions"));
                } else if (securityEvent.getSecurityEventType() == WSSecurityEventConstants.EncryptedPart) {
                    EncryptedPartSecurityEvent encryptedPartSecurityEvent = (EncryptedPartSecurityEvent) securityEvent;
                    Assert.assertNotNull(encryptedPartSecurityEvent.getXmlSecEvent());
                    Assert.assertNotNull(encryptedPartSecurityEvent.getSecurityToken());
                    Assert.assertNotNull(encryptedPartSecurityEvent.getElementPath());
                    final QName expectedElementName = new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body");
                    Assert.assertEquals(encryptedPartSecurityEvent.getXmlSecEvent().asStartElement().getName(), expectedElementName);
                    Assert.assertEquals(encryptedPartSecurityEvent.getElementPath().size(), 2);
                    Assert.assertEquals(encryptedPartSecurityEvent.getElementPath().get(encryptedPartSecurityEvent.getElementPath().size() - 1), expectedElementName);
                }
            }

            EncryptedPartSecurityEvent encryptedPartSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.EncryptedPart);
            OperationSecurityEvent operationSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.Operation);
            String encryptedPartCorrelationID = encryptedPartSecurityEvent.getCorrelationID();
            String operationCorrelationID = operationSecurityEvent.getCorrelationID();

            List<SecurityEvent> operationSecurityEvents = new ArrayList<SecurityEvent>();
            List<SecurityEvent> encryptedPartSecurityEvents = new ArrayList<SecurityEvent>();

            List<SecurityEvent> securityEvents = securityEventListener.getReceivedSecurityEvents();
            for (int i = 0; i < securityEvents.size(); i++) {
                SecurityEvent securityEvent = securityEvents.get(i);
                if (securityEvent.getCorrelationID().equals(encryptedPartCorrelationID)) {
                    encryptedPartSecurityEvents.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(operationCorrelationID)) {
                    operationSecurityEvents.add(securityEvent);
                }
            }

            org.junit.Assert.assertEquals(4, encryptedPartSecurityEvents.size());
            org.junit.Assert.assertEquals(securityEventListener.getReceivedSecurityEvents().size(),
                    operationSecurityEvents.size() + encryptedPartSecurityEvents.size());
        }
    }

    /**
     * rsa-oaep-mgf1p, Digest:SHA256, MGF:SHA1, PSource: None
     */
    @Test
    public void testKeyWrappingRSAOAEPMGF1AESGCM128Outbound() throws Exception {
        ByteArrayOutputStream baos;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.ENCRYPT};
            securityProperties.setOutAction(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionSymAlgorithm("http://www.w3.org/2009/xmlenc11#aes128-gcm");
            securityProperties.setEncryptionKeyTransportAlgorithm("http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p");

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p']");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_DataReference.getNamespaceURI(), WSSConstants.TAG_xenc_DataReference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            xPathExpression = getXPath("/env:Envelope/env:Body/xenc:EncryptedData/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2009/xmlenc11#aes128-gcm']");
            node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            Assert.assertEquals(node.getParentNode().getParentNode().getLocalName(), "Body");
            NodeList childNodes = node.getParentNode().getParentNode().getChildNodes();
            for (int i = 0; i < childNodes.getLength(); i++) {
                Node child = childNodes.item(i);
                if (child.getNodeType() == Node.TEXT_NODE) {
                    Assert.assertEquals(child.getTextContent().trim(), "");
                } else if (child.getNodeType() == Node.ELEMENT_NODE) {
                    Assert.assertEquals(child, nodeList.item(0));
                } else {
                    Assert.fail("Unexpected Node encountered");
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
    public void testKeyWrappingRSAOAEPMGF1AESGCM128Inbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.ENCRYPT;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.ENC_SYM_ALGO, "http://www.w3.org/2009/xmlenc11#aes128-gcm");
            properties.put(WSHandlerConstants.ENC_KEY_TRANSPORT, "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p']");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);

            xPathExpression = getXPath("/env:Envelope/env:Body/xenc:EncryptedData/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2009/xmlenc11#aes128-gcm']");
            node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
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
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }
    }

    /**
    * rsa-oaep-mgf1p, Digest:SHA256, MGF:SHA1, PSource: None
    */
    @Test
    public void testKeyWrappingRSAOAEPAESGCM192SHA256Outbound() throws Exception {
        ByteArrayOutputStream baos;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.ENCRYPT};
            securityProperties.setOutAction(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionSymAlgorithm("http://www.w3.org/2009/xmlenc11#aes192-gcm");
            securityProperties.setEncryptionKeyTransportAlgorithm("http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p");
            securityProperties.setEncryptionKeyTransportDigestAlgorithm("http://www.w3.org/2001/04/xmlenc#sha256");

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p']");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod/dsig:DigestMethod[@Algorithm='http://www.w3.org/2001/04/xmlenc#sha256']");
            node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_DataReference.getNamespaceURI(), WSSConstants.TAG_xenc_DataReference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            xPathExpression = getXPath("/env:Envelope/env:Body/xenc:EncryptedData/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2009/xmlenc11#aes192-gcm']");
            node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            Assert.assertEquals(node.getParentNode().getParentNode().getLocalName(), "Body");
            NodeList childNodes = node.getParentNode().getParentNode().getChildNodes();
            for (int i = 0; i < childNodes.getLength(); i++) {
                Node child = childNodes.item(i);
                if (child.getNodeType() == Node.TEXT_NODE) {
                    Assert.assertEquals(child.getTextContent().trim(), "");
                } else if (child.getNodeType() == Node.ELEMENT_NODE) {
                    Assert.assertEquals(child, nodeList.item(0));
                } else {
                    Assert.fail("Unexpected Node encountered");
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
    public void testKeyWrappingRSAOAEPAESGMC192SHA256Inbound() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.ENCRYPT;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.ENC_SYM_ALGO, "http://www.w3.org/2009/xmlenc11#aes192-gcm");
            properties.put(WSHandlerConstants.ENC_KEY_TRANSPORT, "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p");
            properties.put(WSHandlerConstants.ENC_DIGEST_ALGO, "http://www.w3.org/2001/04/xmlenc#sha256");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p']");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);

            xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod/dsig:DigestMethod[@Algorithm='http://www.w3.org/2001/04/xmlenc#sha256']");
            node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);

            xPathExpression = getXPath("/env:Envelope/env:Body/xenc:EncryptedData/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2009/xmlenc11#aes192-gcm']");
            node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
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
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }
    }

    /**
     * rsa-oaep, Digest:SHA384, MGF:SHA1, PSource: None
     */
    @Test
    public void testKeyWrappingRSAOAEPAES192GCMSHA384MGF1sha384Outbound() throws Exception {
        ByteArrayOutputStream baos;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.ENCRYPT};
            securityProperties.setOutAction(actions);
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
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2009/xmlenc11#rsa-oaep']");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod/dsig:DigestMethod[@Algorithm='http://www.w3.org/2001/04/xmldsig-more#sha384']");
            node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod/xenc11:MGF[@Algorithm='http://www.w3.org/2009/xmlenc11#mgf1sha384']");
            node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_DataReference.getNamespaceURI(), WSSConstants.TAG_xenc_DataReference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            xPathExpression = getXPath("/env:Envelope/env:Body/xenc:EncryptedData/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2009/xmlenc11#aes192-gcm']");
            node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            Assert.assertEquals(node.getParentNode().getParentNode().getLocalName(), "Body");
            NodeList childNodes = node.getParentNode().getParentNode().getChildNodes();
            for (int i = 0; i < childNodes.getLength(); i++) {
                Node child = childNodes.item(i);
                if (child.getNodeType() == Node.TEXT_NODE) {
                    Assert.assertEquals(child.getTextContent().trim(), "");
                } else if (child.getNodeType() == Node.ELEMENT_NODE) {
                    Assert.assertEquals(child, nodeList.item(0));
                } else {
                    Assert.fail("Unexpected Node encountered");
                }
            }
        }
        //done encryption; now test decryption:
        {
            String action = WSHandlerConstants.ENCRYPT;
            doInboundSecurityWithWSS4J_1(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testKeyWrappingRSAOAEPAES192GCMSHA384MGF1sha1Inbound() throws Exception {

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
            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2009/xmlenc11#rsa-oaep']");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);

            xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod/dsig:DigestMethod[@Algorithm='http://www.w3.org/2001/04/xmldsig-more#sha384']");
            node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);

            xPathExpression = getXPath("/env:Envelope/env:Body/xenc:EncryptedData/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2009/xmlenc11#aes192-gcm']");
            node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
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
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }
    }

    /**
     * rsa-oaep, Digest:SHA512, MGF:SHA1, PSource: Specified 8 bytes
     */

    @Test
    public void testKeyWrappingRSAOAEPAESGCM192SHA384MGF1SHA384PSourceOutbound() throws Exception {
        ByteArrayOutputStream baos;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            WSSConstants.Action[] actions = new WSSConstants.Action[]{WSSConstants.ENCRYPT};
            securityProperties.setOutAction(actions);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionSymAlgorithm("http://www.w3.org/2009/xmlenc11#aes192-gcm");
            securityProperties.setEncryptionKeyTransportAlgorithm("http://www.w3.org/2009/xmlenc11#rsa-oaep");
            securityProperties.setEncryptionKeyTransportDigestAlgorithm("http://www.w3.org/2001/04/xmldsig-more#sha384");
            securityProperties.setEncryptionKeyTransportMGFAlgorithm("http://www.w3.org/2009/xmlenc11#mgf1sha384");
            securityProperties.setEncryptionKeyTransportOAEPParams(Base64.decode("ZHVtbXkxMjM=".getBytes("UTF-8")));

            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            baos = doOutboundSecurity(securityProperties, sourceDocument);

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2009/xmlenc11#rsa-oaep']");
            Node node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod/xenc:OAEPparams");
            node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod/dsig:DigestMethod[@Algorithm='http://www.w3.org/2001/04/xmldsig-more#sha384']");
            node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod/xenc11:MGF[@Algorithm='http://www.w3.org/2009/xmlenc11#mgf1sha384']");
            node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_DataReference.getNamespaceURI(), WSSConstants.TAG_xenc_DataReference.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);

            xPathExpression = getXPath("/env:Envelope/env:Body/xenc:EncryptedData/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2009/xmlenc11#aes192-gcm']");
            node = (Node) xPathExpression.evaluate(document, XPathConstants.NODE);
            Assert.assertNotNull(node);

            Assert.assertEquals(node.getParentNode().getParentNode().getLocalName(), "Body");
            NodeList childNodes = node.getParentNode().getParentNode().getChildNodes();
            for (int i = 0; i < childNodes.getLength(); i++) {
                Node child = childNodes.item(i);
                if (child.getNodeType() == Node.TEXT_NODE) {
                    Assert.assertEquals(child.getTextContent().trim(), "");
                } else if (child.getNodeType() == Node.ELEMENT_NODE) {
                    Assert.assertEquals(child, nodeList.item(0));
                } else {
                    Assert.fail("Unexpected Node encountered");
                }
            }
        }
        //done encryption; now test decryption:
        {
            String action = WSHandlerConstants.ENCRYPT;
            doInboundSecurityWithWSS4J_1(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test(enabled = false) //WSS4J does not support OAEPParams atm
    public void testKeyWrappingRSAOAEPAESGCM192SHA384MGF1SHA384PSourceInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.ENCRYPT;
            Properties properties = new Properties();
            properties.put(WSHandlerConstants.ENC_SYM_ALGO, "http://www.w3.org/2009/xmlenc11#aes192-gcm");
            properties.put(WSHandlerConstants.ENC_KEY_TRANSPORT, "http://www.w3.org/2009/xmlenc11#rsa-oaep");
            properties.put(WSHandlerConstants.ENC_DIGEST_ALGO, "http://www.w3.org/2001/04/xmldsig-more#sha384");
            properties.put(WSHandlerConstants.ENC_MGF_ALGO, "http://www.w3.org/2009/xmlenc11#mgf1sha384");
            //properties.put(WSHandlerConstants.ENC_OAEP_PARAMS, Base64.decode("ZHVtbXkxMjM=".getBytes("UTF-8")));

            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            XPathExpression xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2009/xmlenc11#rsa-oaep']");
            Node node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);

            xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod/xenc:OAEPparams");
            node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);

            xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod/dsig:DigestMethod[@Algorithm='http://www.w3.org/2001/04/xmldsig-more#sha384']");
            node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);

            xPathExpression = getXPath("/env:Envelope/env:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod/dsig:MGF[@Algorithm='http://www.w3.org/2009/xmlenc11#mgf1sha384']");
            node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);

            xPathExpression = getXPath("/env:Envelope/env:Body/xenc:EncryptedData/xenc:EncryptionMethod[@Algorithm='http://www.w3.org/2009/xmlenc11#aes192-gcm']");
            node = (Node) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
            Assert.assertNotNull(node);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
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
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_wsse_Security.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }
    }
}
