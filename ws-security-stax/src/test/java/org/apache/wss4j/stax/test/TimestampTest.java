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
import java.nio.charset.StandardCharsets;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.wss4j.common.ConfigurationConstants;
import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.DateUtil;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.setup.ConfigurationConverter;
import org.apache.wss4j.stax.setup.InboundWSSec;
import org.apache.wss4j.stax.setup.OutboundWSSec;
import org.apache.wss4j.stax.setup.WSSec;
import org.apache.wss4j.stax.test.utils.StAX2DOM;
import org.apache.wss4j.stax.test.utils.XmlReaderToWriter;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.junit.Assert;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class TimestampTest extends AbstractTestBase {

    @Test
    public void testTimestampDefaultConfigurationOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
            actions.add(WSSConstants.TIMESTAMP);
            securityProperties.setActions(actions);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_WSU_TIMESTAMP.getNamespaceURI(), WSSConstants.TAG_WSU_TIMESTAMP.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            Element created = (Element) ((Element) nodeList.item(0)).getElementsByTagNameNS(WSSConstants.TAG_WSU_CREATED.getNamespaceURI(), WSSConstants.TAG_WSU_CREATED.getLocalPart()).item(0);
            Element expires = (Element) ((Element) nodeList.item(0)).getElementsByTagNameNS(WSSConstants.TAG_WSU_EXPIRES.getNamespaceURI(), WSSConstants.TAG_WSU_EXPIRES.getLocalPart()).item(0);

            ZonedDateTime createdDateTime = ZonedDateTime.parse(created.getTextContent());
            ZonedDateTime expiresDateTime = ZonedDateTime.parse(expires.getTextContent());

            ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);
            Assert.assertFalse(now.isBefore(createdDateTime));
            Assert.assertTrue(now.isBefore(expiresDateTime));

            Assert.assertTrue(createdDateTime.plusSeconds(301L).isAfter(expiresDateTime));
        }

        //done timestamp; now test timestamp verification:
        {
            String action = WSHandlerConstants.TIMESTAMP;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testTimestampDefaultConfigurationInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.TIMESTAMP;
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, new Properties());

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_WSU_TIMESTAMP.getNamespaceURI(), WSSConstants.TAG_WSU_TIMESTAMP.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done timestamp; now test timestamp-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_WSU_TIMESTAMP.getNamespaceURI(), WSSConstants.TAG_WSU_TIMESTAMP.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());
        }
    }

    @Test
    public void testTimestampTTLOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
            actions.add(WSSConstants.TIMESTAMP);
            securityProperties.setActions(actions);
            securityProperties.setTimestampTTL(3600);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_WSU_TIMESTAMP.getNamespaceURI(), WSSConstants.TAG_WSU_TIMESTAMP.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            Element created = (Element) ((Element) nodeList.item(0)).getElementsByTagNameNS(WSSConstants.TAG_WSU_CREATED.getNamespaceURI(), WSSConstants.TAG_WSU_CREATED.getLocalPart()).item(0);
            Element expires = (Element) ((Element) nodeList.item(0)).getElementsByTagNameNS(WSSConstants.TAG_WSU_EXPIRES.getNamespaceURI(), WSSConstants.TAG_WSU_EXPIRES.getLocalPart()).item(0);

            ZonedDateTime createdDateTime = ZonedDateTime.parse(created.getTextContent());
            ZonedDateTime expiresDateTime = ZonedDateTime.parse(expires.getTextContent());
            
            Assert.assertTrue(createdDateTime.isBefore(expiresDateTime));
            
            ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);
            Assert.assertFalse(now.isBefore(createdDateTime));
            Assert.assertTrue(now.isBefore(expiresDateTime));

            Assert.assertTrue(createdDateTime.plusSeconds(3601L).isAfter(expiresDateTime));
        }

        //done timestamp; now test timestamp verification:
        {
            String action = WSHandlerConstants.TIMESTAMP;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testTimestampExpiredInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.TIMESTAMP;
            Properties outboundProperties = new Properties();
            outboundProperties.setProperty(WSHandlerConstants.TTL_TIMESTAMP, "1");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, outboundProperties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_WSU_TIMESTAMP.getNamespaceURI(), WSSConstants.TAG_WSU_TIMESTAMP.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        Thread.sleep(1500);

        //done timestamp; now test timestamp-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties, false, true);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            try {
                StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                Assert.fail("Expected XMLStreamException");
            } catch (XMLStreamException e) {
                Assert.assertNotNull(e.getCause());
                Assert.assertTrue(e.getCause() instanceof WSSecurityException);
                Assert.assertEquals(((WSSecurityException) e.getCause()).getFaultCode(), WSSecurityException.MESSAGE_EXPIRED);
            }
        }
    }

    @Test
    public void testTimestampExpiredEncryptedInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.ENCRYPT;
            Properties outboundProperties = new Properties();
            outboundProperties.setProperty(WSHandlerConstants.TTL_TIMESTAMP, "1");
            outboundProperties.setProperty(WSHandlerConstants.ENCRYPTION_PARTS, "{Element}{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp;");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, outboundProperties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        Thread.sleep(1500);

        //done timestamp; now test timestamp-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties, false, true);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            try {
                StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                Assert.fail("Expected XMLStreamException");
            } catch (XMLStreamException e) {
                Assert.assertNotNull(e.getCause());
                Assert.assertTrue(e.getCause() instanceof WSSecurityException);
                Assert.assertEquals(((WSSecurityException) e.getCause()).getFaultCode(), WSSecurityException.MESSAGE_EXPIRED);
            }
        }
    }

    @Test
    public void testTimestampInNearFutureInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.TIMESTAMP;
            Properties outboundProperties = new Properties();
            outboundProperties.setProperty(WSHandlerConstants.TTL_TIMESTAMP, "1");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, outboundProperties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_WSU_TIMESTAMP.getNamespaceURI(), WSSConstants.TAG_WSU_TIMESTAMP.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            Element created = (Element) ((Element) nodeList.item(0)).getElementsByTagNameNS(WSSConstants.TAG_WSU_CREATED.getNamespaceURI(), WSSConstants.TAG_WSU_CREATED.getLocalPart()).item(0);
            Element expires = (Element) ((Element) nodeList.item(0)).getElementsByTagNameNS(WSSConstants.TAG_WSU_EXPIRES.getNamespaceURI(), WSSConstants.TAG_WSU_EXPIRES.getLocalPart()).item(0);

            ZonedDateTime createdDateTime = ZonedDateTime.now(ZoneOffset.UTC).plusSeconds(40L);
            created.setTextContent(DateUtil.getDateTimeFormatter(true).format(createdDateTime));

            ZonedDateTime expiresDateTime = ZonedDateTime.now(ZoneOffset.UTC).plusSeconds(300L);
            expires.setTextContent(DateUtil.getDateTimeFormatter(true).format(expiresDateTime));

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done timestamp; now test timestamp-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
        }
    }

    @Test
    public void testTimestampInFutureInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.TIMESTAMP;
            Properties outboundProperties = new Properties();
            outboundProperties.setProperty(WSHandlerConstants.TTL_TIMESTAMP, "1");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, outboundProperties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_WSU_TIMESTAMP.getNamespaceURI(), WSSConstants.TAG_WSU_TIMESTAMP.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            Element created = (Element) ((Element) nodeList.item(0)).getElementsByTagNameNS(WSSConstants.TAG_WSU_CREATED.getNamespaceURI(), WSSConstants.TAG_WSU_CREATED.getLocalPart()).item(0);
            Element expires = (Element) ((Element) nodeList.item(0)).getElementsByTagNameNS(WSSConstants.TAG_WSU_EXPIRES.getNamespaceURI(), WSSConstants.TAG_WSU_EXPIRES.getLocalPart()).item(0);

            ZonedDateTime createdDateTime = ZonedDateTime.now(ZoneOffset.UTC).plusHours(2L);
            created.setTextContent(DateUtil.getDateTimeFormatter(true).format(createdDateTime));

            ZonedDateTime expiresDateTime = ZonedDateTime.now(ZoneOffset.UTC).plusHours(2L).plusSeconds(300L);
            expires.setTextContent(DateUtil.getDateTimeFormatter(true).format(expiresDateTime));
            
            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done timestamp; now test timestamp-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties, false, true);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            try {
                StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                Assert.fail("Expected XMLStreamException");
            } catch (XMLStreamException e) {
                Assert.assertNotNull(e.getCause());
                Assert.assertTrue(e.getCause() instanceof WSSecurityException);
                Assert.assertEquals(((WSSecurityException) e.getCause()).getFaultCode(), WSSecurityException.MESSAGE_EXPIRED);
            }
        }

        // now allow future TTL of 2 hours +
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.setTimeStampFutureTTL(2 * 60 * 60 + 100);

            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
        }
    }

    @Test
    public void testTimestampStrictOffInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.TIMESTAMP;
            Properties outboundProperties = new Properties();
            outboundProperties.setProperty(WSHandlerConstants.TTL_TIMESTAMP, "1");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, outboundProperties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_WSU_TIMESTAMP.getNamespaceURI(), WSSConstants.TAG_WSU_TIMESTAMP.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        Thread.sleep(1000);

        //done timestamp; now test timestamp-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.setStrictTimestampCheck(false);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
        }
    }

    @Test
    public void testTimestampTTLInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.TIMESTAMP;
            Properties outboundProperties = new Properties();
            outboundProperties.setProperty(WSHandlerConstants.TTL_TIMESTAMP, "300");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, outboundProperties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_WSU_TIMESTAMP.getNamespaceURI(), WSSConstants.TAG_WSU_TIMESTAMP.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        Thread.sleep(1500);

        //done timestamp; now test timestamp-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.setTimestampTTL(1);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties, false, true);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            try {
                StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                Assert.fail("Expected XMLStreamException");
            } catch (XMLStreamException e) {
                Assert.assertNotNull(e.getCause());
                Assert.assertTrue(e.getCause() instanceof WSSecurityException);
                Assert.assertEquals(((WSSecurityException) e.getCause()).getFaultCode(), WSSecurityException.MESSAGE_EXPIRED);
            }
        }
    }

    @Test
    public void testTimestampNoCreatedDateInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.TIMESTAMP;
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, new Properties());

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_WSU_TIMESTAMP.getNamespaceURI(), WSSConstants.TAG_WSU_TIMESTAMP.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());
            for (int i = 0; i < nodeList.item(0).getChildNodes().getLength(); i++) {
                Node node = nodeList.item(0).getChildNodes().item(i);
                if (node.getNodeType() == Node.ELEMENT_NODE && node.getLocalName().equals("Created")) {
                    node.getParentNode().removeChild(node);
                }
            }

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done timestamp; now test timestamp-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.addIgnoreBSPRule(BSPRule.R3203);
            securityProperties.addIgnoreBSPRule(BSPRule.R3221);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties, false, true);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            try {
                StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                Assert.fail("Expected XMLStreamException");
            } catch (XMLStreamException e) {
                Throwable throwable = e.getCause();
                Assert.assertNotNull(throwable);
                Assert.assertTrue(throwable instanceof WSSecurityException);
                Assert.assertEquals(((WSSecurityException) throwable).getFaultCode(), WSSecurityException.INVALID_SECURITY);
            }
        }
    }

    @Test
    public void testTimestampNoExpiresDateInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.TIMESTAMP;
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, new Properties());

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_WSU_TIMESTAMP.getNamespaceURI(), WSSConstants.TAG_WSU_TIMESTAMP.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());
            for (int i = 0; i < nodeList.item(0).getChildNodes().getLength(); i++) {
                Node node = nodeList.item(0).getChildNodes().item(i);
                if (node.getNodeType() == Node.ELEMENT_NODE && node.getLocalName().equals("Expires")) {
                    node.getParentNode().removeChild(node);
                }
            }

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done timestamp; now test timestamp-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_WSU_TIMESTAMP.getNamespaceURI(), WSSConstants.TAG_WSU_TIMESTAMP.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());
        }
    }

    @Test
    public void testTimestampInvalidNoExpiresDateInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.TIMESTAMP;
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, new Properties());

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_WSU_TIMESTAMP.getNamespaceURI(), WSSConstants.TAG_WSU_TIMESTAMP.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());
            for (int i = 0; i < nodeList.item(0).getChildNodes().getLength(); i++) {
                Node node = nodeList.item(0).getChildNodes().item(i);
                if (node.getNodeType() == Node.ELEMENT_NODE && node.getLocalName().equals("Expires")) {
                    node.getParentNode().removeChild(node);
                }
            }

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        // Require a Timestamp Expires Element - should fail
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.setRequireTimestampExpires(true);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            try {
                StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                fail("Failure expected on no Expires Element");
            } catch (XMLStreamException e) {
                Assert.assertNotNull(e.getCause());
                Assert.assertTrue(e.getCause() instanceof WSSecurityException);
            }
        }

        // No Timestamp Expires Element required - should pass
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_WSU_TIMESTAMP.getNamespaceURI(), WSSConstants.TAG_WSU_TIMESTAMP.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());
        }
    }

    @Test
    public void testTimestampNoChildsInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.TIMESTAMP;
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, new Properties());

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_WSU_TIMESTAMP.getNamespaceURI(), WSSConstants.TAG_WSU_TIMESTAMP.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            List<Node> nodesToRemove = new ArrayList<>();
            for (int i = 0; i < nodeList.item(0).getChildNodes().getLength(); i++) {
                Node node = nodeList.item(0).getChildNodes().item(i);
                if (node.getNodeType() == Node.ELEMENT_NODE
                        && (node.getLocalName().equals("Created")) || node.getLocalName().equals("Expires")) {
                    nodesToRemove.add(node);
                }
            }
            for (int i = 0; i < nodesToRemove.size(); i++) {
                Node node = nodesToRemove.get(i);
                node.getParentNode().removeChild(node);
            }

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done timestamp; now test timestamp-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.addIgnoreBSPRule(BSPRule.R3203);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties, false, true);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            try {
                StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                Assert.fail("Expected XMLStreamException");
            } catch (XMLStreamException e) {
                Throwable throwable = e.getCause();
                Assert.assertNotNull(throwable);
                Assert.assertTrue(throwable instanceof WSSecurityException);
                Assert.assertEquals(((WSSecurityException) throwable).getFaultCode(), WSSecurityException.INVALID_SECURITY);
            }
        }
    }

    @Test
    public void testDoubleTimestamp() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.TIMESTAMP;
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, new Properties());

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_WSU_TIMESTAMP.getNamespaceURI(), WSSConstants.TAG_WSU_TIMESTAMP.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            Node parentNode = nodeList.item(0).getParentNode();
            Node node = nodeList.item(0).cloneNode(true);
            securedDocument.adoptNode(node);
            parentNode.appendChild(node);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done timestamp; now test timestamp-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties, false, true);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            try {
                StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
                Assert.fail("Expected XMLStreamException");
            } catch (XMLStreamException e) {
                Throwable throwable = e.getCause();
                Assert.assertNotNull(throwable);
                Assert.assertTrue(throwable instanceof WSSecurityException);
                Assert.assertEquals(((WSSecurityException) throwable).getFaultCode(), WSSecurityException.INVALID_SECURITY);
            }
        }
    }

    @Test
    public void testTimestampPropertiesOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            Map<String, Object> config = new HashMap<>();
            config.put(ConfigurationConstants.ACTION, ConfigurationConstants.TIMESTAMP);

            WSSSecurityProperties securityProperties = ConfigurationConverter.convert(config);
            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_WSU_TIMESTAMP.getNamespaceURI(), WSSConstants.TAG_WSU_TIMESTAMP.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            Element created = (Element) ((Element) nodeList.item(0)).getElementsByTagNameNS(WSSConstants.TAG_WSU_CREATED.getNamespaceURI(), WSSConstants.TAG_WSU_CREATED.getLocalPart()).item(0);
            Element expires = (Element) ((Element) nodeList.item(0)).getElementsByTagNameNS(WSSConstants.TAG_WSU_EXPIRES.getNamespaceURI(), WSSConstants.TAG_WSU_EXPIRES.getLocalPart()).item(0);

            ZonedDateTime createdDateTime = ZonedDateTime.parse(created.getTextContent());
            ZonedDateTime expiresDateTime = ZonedDateTime.parse(expires.getTextContent());
            
            Assert.assertTrue(createdDateTime.isBefore(expiresDateTime));
            
            ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);
            Assert.assertFalse(now.isBefore(createdDateTime));
            Assert.assertTrue(now.isBefore(expiresDateTime));

            Assert.assertTrue(createdDateTime.plusSeconds(301L).isAfter(expiresDateTime));
        }

        //done timestamp; now test timestamp verification:
        {
            String action = WSHandlerConstants.TIMESTAMP;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @Test
    public void testTimestampPropertiesInbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.TIMESTAMP;
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, new Properties());

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_WSU_TIMESTAMP.getNamespaceURI(), WSSConstants.TAG_WSU_TIMESTAMP.getLocalPart());
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        //done timestamp; now test timestamp-verification:
        {
            Map<String, Object> config = new HashMap<>();
            config.put(ConfigurationConstants.ACTION, ConfigurationConstants.TIMESTAMP);
            WSSSecurityProperties securityProperties = ConfigurationConverter.convert(config);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);

            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_WSU_TIMESTAMP.getNamespaceURI(), WSSConstants.TAG_WSU_TIMESTAMP.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());
        }
    }
}
