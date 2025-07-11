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
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;

import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.api.stax.ext.WSSConstants;
import org.apache.wss4j.api.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.api.stax.securityEvent.EncryptedPartSecurityEvent;
import org.apache.wss4j.api.stax.securityEvent.OperationSecurityEvent;
import org.apache.wss4j.api.stax.securityEvent.SignedPartSecurityEvent;
import org.apache.wss4j.api.stax.securityEvent.WSSecurityEventConstants;
import org.apache.wss4j.stax.setup.InboundWSSec;
import org.apache.wss4j.stax.setup.OutboundWSSec;
import org.apache.wss4j.stax.setup.WSSec;
import org.apache.wss4j.stax.test.utils.StAX2DOM;
import org.apache.wss4j.stax.test.utils.XmlReaderToWriter;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.securityEvent.EncryptedElementSecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEventListener;
import org.apache.xml.security.stax.securityEvent.SignatureValueSecurityEvent;
import org.apache.xml.security.stax.securityEvent.SignedElementSecurityEvent;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class InteroperabilityTest extends AbstractTestBase {

    @Test
    public void testInteroperabilityInbound() throws Exception {

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

        String action = WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPTION;
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

        WSSecurityEventConstants.Event[] expectedSecurityEvents = new WSSecurityEventConstants.Event[]{
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.X509Token,
                WSSecurityEventConstants.X509Token,
                WSSecurityEventConstants.SignatureValue,
                WSSecurityEventConstants.TIMESTAMP,
                WSSecurityEventConstants.SignedElement,
                WSSecurityEventConstants.SIGNED_PART,
                WSSecurityEventConstants.ENCRYPTED_PART,
                WSSecurityEventConstants.OPERATION,
        };
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener(expectedSecurityEvents);
        Document document = doInboundSecurity(securityProperties,
                xmlInputFactory.createXMLStreamReader(
                        new ByteArrayInputStream(baos.toByteArray())), securityEventListener);

        //read the whole stream:
        transformer = TRANSFORMER_FACTORY.newTransformer();
        transformer.transform(new DOMSource(document), new StreamResult(
                new OutputStream() {
                    @Override
                    public void write(int b) throws IOException {
                        // > /dev/null
                    }
                }
        ));
        securityEventListener.compare();

        EncryptedPartSecurityEvent encryptedPartSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.ENCRYPTED_PART);
        List<SignedElementSecurityEvent> signedElementSecurityEventList = securityEventListener.getSecurityEvents(WSSecurityEventConstants.SignedElement);
        List<SignedPartSecurityEvent> signedPartSecurityEventList = securityEventListener.getSecurityEvents(WSSecurityEventConstants.SIGNED_PART);
        SignatureValueSecurityEvent signatureValueSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.SignatureValue);
        OperationSecurityEvent operationSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.OPERATION);
        String encryptedPartCorrelationID = encryptedPartSecurityEvent.getCorrelationID();
        String signedElementCorrelationID1 = signedElementSecurityEventList.get(0).getCorrelationID();
        String signedElementCorrelationID2 = signedPartSecurityEventList.get(0).getCorrelationID();
        String signatureValueCorrelationID = signatureValueSecurityEvent.getCorrelationID();
        String operationCorrelationID = operationSecurityEvent.getCorrelationID();

        List<SecurityEvent> operationSecurityEvents = new ArrayList<>();
        List<SecurityEvent> encryptedPartSecurityEvents = new ArrayList<>();
        List<SecurityEvent> signedElementSecurityEvents1 = new ArrayList<>();
        List<SecurityEvent> signedElementSecurityEvents2 = new ArrayList<>();
        List<SecurityEvent> signatureValueSecurityEvents = new ArrayList<>();

        List<SecurityEvent> securityEvents = securityEventListener.getReceivedSecurityEvents();
        for (SecurityEvent securityEvent : securityEvents) {
            if (securityEvent.getCorrelationID().equals(encryptedPartCorrelationID)) {
                encryptedPartSecurityEvents.add(securityEvent);
            } else if (securityEvent.getCorrelationID().equals(signedElementCorrelationID1)) {
                signedElementSecurityEvents1.add(securityEvent);
            } else if (securityEvent.getCorrelationID().equals(signedElementCorrelationID2)) {
                signedElementSecurityEvents2.add(securityEvent);
            } else if (securityEvent.getCorrelationID().equals(signatureValueCorrelationID)) {
                signatureValueSecurityEvents.add(securityEvent);
            } else if (securityEvent.getCorrelationID().equals(operationCorrelationID)) {
                operationSecurityEvents.add(securityEvent);
            }
        }

        assertEquals(4, encryptedPartSecurityEvents.size());
        assertEquals(3, signedElementSecurityEvents1.size());
        assertEquals(3, signedElementSecurityEvents2.size());
        assertEquals(4, signatureValueSecurityEvents.size());
        assertEquals(securityEventListener.getReceivedSecurityEvents().size(),
                operationSecurityEvents.size() +
                        encryptedPartSecurityEvents.size() +
                        signedElementSecurityEvents1.size() +
                        signedElementSecurityEvents2.size() +
                        signatureValueSecurityEvents.size() +
                        1 //the timestamp
        );
    }

    @Test
    public void testInteroperabilityInboundSOAP12() throws Exception {

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.2.xml");

        String action = WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPTION;
        Properties properties = new Properties();
        properties.setProperty(WSHandlerConstants.SIGNATURE_PARTS, "{Element}{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp;{Element}{http://www.w3.org/2003/05/soap-envelope}Body;");
        Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
        transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));

        WSSSecurityProperties securityProperties = new WSSSecurityProperties();
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());
        securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        WSSecurityEventConstants.Event[] expectedSecurityEvents = new WSSecurityEventConstants.Event[]{
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.X509Token,
                WSSecurityEventConstants.X509Token,
                WSSecurityEventConstants.SignatureValue,
                WSSecurityEventConstants.TIMESTAMP,
                WSSecurityEventConstants.SignedElement,
                WSSecurityEventConstants.SIGNED_PART,
                WSSecurityEventConstants.ENCRYPTED_PART,
                WSSecurityEventConstants.OPERATION,
        };
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener(expectedSecurityEvents);
        Document document = doInboundSecurity(
                securityProperties,
                xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), securityEventListener);

        //read the whole stream:
        transformer = TRANSFORMER_FACTORY.newTransformer();
        transformer.transform(new DOMSource(document), new StreamResult(
                new OutputStream() {
                    @Override
                    public void write(int b) throws IOException {
                        // > /dev/null
                    }
                }
        ));
        securityEventListener.compare();
    }

    @Test
    public void testInteroperabilityEncryptedSignatureInbound() throws Exception {

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

        String action = WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPTION;
        Properties properties = new Properties();
        properties.setProperty(WSHandlerConstants.SIGNATURE_PARTS, "{Element}{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp;{Element}{http://schemas.xmlsoap.org/soap/envelope/}Body;");
        properties.setProperty(WSHandlerConstants.ENCRYPTION_PARTS, "{Element}{http://www.w3.org/2000/09/xmldsig#}Signature;{Content}{http://schemas.xmlsoap.org/soap/envelope/}Body;");
        Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
        transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));

        WSSSecurityProperties securityProperties = new WSSSecurityProperties();
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());
        securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        WSSecurityEventConstants.Event[] expectedSecurityEvents = new WSSecurityEventConstants.Event[]{
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.X509Token,
                WSSecurityEventConstants.X509Token,
                WSSecurityEventConstants.EncryptedElement,
                WSSecurityEventConstants.SignatureValue,
                WSSecurityEventConstants.TIMESTAMP,
                WSSecurityEventConstants.SignedElement,
                WSSecurityEventConstants.SIGNED_PART,
                WSSecurityEventConstants.ENCRYPTED_PART,
                WSSecurityEventConstants.OPERATION,
        };
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener(expectedSecurityEvents);
        Document document = doInboundSecurity(
                securityProperties,
                xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), securityEventListener);

        //read the whole stream:
        transformer = TRANSFORMER_FACTORY.newTransformer();
        transformer.transform(new DOMSource(document), new StreamResult(
                new OutputStream() {
                    @Override
                    public void write(int b) throws IOException {
                        // > /dev/null
                    }
                }
        ));

        securityEventListener.compare();

        EncryptedElementSecurityEvent encryptedElementSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.EncryptedElement);
        EncryptedPartSecurityEvent encryptedPartSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.ENCRYPTED_PART);
        List<SignedElementSecurityEvent> signedElementSecurityEventList = securityEventListener.getSecurityEvents(WSSecurityEventConstants.SignedElement);
        List<SignedPartSecurityEvent> signedPartSecurityEventList = securityEventListener.getSecurityEvents(WSSecurityEventConstants.SIGNED_PART);
        SignatureValueSecurityEvent signatureValueSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.SignatureValue);
        OperationSecurityEvent operationSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.OPERATION);
        String encryptedElementCorrelationID = encryptedElementSecurityEvent.getCorrelationID();
        String encryptedPartCorrelationID = encryptedPartSecurityEvent.getCorrelationID();
        String signedElementCorrelationID1 = signedElementSecurityEventList.get(0).getCorrelationID();
        String signedElementCorrelationID2 = signedPartSecurityEventList.get(0).getCorrelationID();
        String signatureValueCorrelationID = signatureValueSecurityEvent.getCorrelationID();
        String operationCorrelationID = operationSecurityEvent.getCorrelationID();

        List<SecurityEvent> operationSecurityEvents = new ArrayList<>();
        List<SecurityEvent> encryptedPartSecurityEvents = new ArrayList<>();
        List<SecurityEvent> encryptedElementSecurityEvents = new ArrayList<>();
        List<SecurityEvent> signedElementSecurityEvents1 = new ArrayList<>();
        List<SecurityEvent> signedElementSecurityEvents2 = new ArrayList<>();
        List<SecurityEvent> signatureValueSecurityEvents = new ArrayList<>();

        List<SecurityEvent> securityEvents = securityEventListener.getReceivedSecurityEvents();
        for (SecurityEvent securityEvent : securityEvents) {
            if (securityEvent.getCorrelationID().equals(encryptedPartCorrelationID)) {
                encryptedPartSecurityEvents.add(securityEvent);
            } else if (securityEvent.getCorrelationID().equals(encryptedElementCorrelationID)) {
                encryptedElementSecurityEvents.add(securityEvent);
            } else if (securityEvent.getCorrelationID().equals(signedElementCorrelationID1)) {
                signedElementSecurityEvents1.add(securityEvent);
            } else if (securityEvent.getCorrelationID().equals(signedElementCorrelationID2)) {
                signedElementSecurityEvents2.add(securityEvent);
            } else if (securityEvent.getCorrelationID().equals(signatureValueCorrelationID)) {
                signatureValueSecurityEvents.add(securityEvent);
            } else if (securityEvent.getCorrelationID().equals(operationCorrelationID)) {
                operationSecurityEvents.add(securityEvent);
            }
        }

        assertEquals(3, encryptedPartSecurityEvents.size());
        assertEquals(3, encryptedElementSecurityEvents.size());
        assertEquals(3, signedElementSecurityEvents1.size());
        assertEquals(3, signedElementSecurityEvents2.size());
        assertEquals(4, signatureValueSecurityEvents.size());
        assertEquals(securityEventListener.getReceivedSecurityEvents().size(),
                operationSecurityEvents.size() +
                        encryptedPartSecurityEvents.size() +
                        encryptedElementSecurityEvents.size() +
                        signedElementSecurityEvents1.size() +
                        signedElementSecurityEvents2.size() +
                        signatureValueSecurityEvents.size() +
                        1 //the timestamp
        );
    }

    //Not supported ATM: Timestamp encrypted and then Signed
    /*
    @Test(invocationCount = 1)
    public void testInteroperabilitySignedEncryptedTimestampInbound() throws Exception {

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

        String action = WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.ENCRYPTION + " " + WSHandlerConstants.SIGNATURE;
        Properties properties = new Properties();
        properties.setProperty(WSHandlerConstants.SIGNATURE_PARTS, "{Element}{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp;{Element}{http://schemas.xmlsoap.org/soap/envelope/}Body;");
        properties.setProperty(WSHandlerConstants.ENCRYPTION_PARTS, "{Content}{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp;{Content}{http://schemas.xmlsoap.org/soap/envelope/}Body;");
        Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
        transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));

        WSSSecurityProperties securityProperties = new WSSSecurityProperties();
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());
        securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

        //read the whole stream:
        transformer = TRANSFORMER_FACTORY.newTransformer();
        //transformer.transform(new DOMSource(document), new StreamResult(System.out));
        transformer.transform(new DOMSource(document), new StreamResult(
                new OutputStream() {
                    @Override
                    public void write(int b) throws IOException {
                        // > /dev/null
                    }
                }
        ));
    }
*/

    @Test
    public void testInteroperabilityInboundReverseOrder() throws Exception {

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

        String action = WSHandlerConstants.ENCRYPTION + " " + WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.TIMESTAMP;
        Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, new Properties());
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
        transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));

        WSSSecurityProperties securityProperties = new WSSSecurityProperties();
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());
        securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        WSSecurityEventConstants.Event[] expectedSecurityEvents = new WSSecurityEventConstants.Event[]{
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.X509Token,
                WSSecurityEventConstants.X509Token,
                WSSecurityEventConstants.TIMESTAMP,
                WSSecurityEventConstants.SignatureValue,
                WSSecurityEventConstants.SIGNED_PART,
                WSSecurityEventConstants.ENCRYPTED_PART,
                WSSecurityEventConstants.OPERATION,
        };
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener(expectedSecurityEvents);
        Document document = doInboundSecurity(
                securityProperties,
                xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), securityEventListener);

        //read the whole stream:
        transformer = TRANSFORMER_FACTORY.newTransformer();
        transformer.transform(new DOMSource(document), new StreamResult(
                new OutputStream() {
                    @Override
                    public void write(int b) throws IOException {
                        // > /dev/null
                    }
                }
        ));
        securityEventListener.compare();

        EncryptedPartSecurityEvent encryptedPartSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.ENCRYPTED_PART);
        List<SignedPartSecurityEvent> signedPartSecurityEvents = securityEventListener.getSecurityEvents(WSSecurityEventConstants.SIGNED_PART);
        SignatureValueSecurityEvent signatureValueSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.SignatureValue);
        OperationSecurityEvent operationSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.OPERATION);
        String encryptedPartCorrelationID = encryptedPartSecurityEvent.getCorrelationID();
        String signedElementCorrelationID1 = signedPartSecurityEvents.get(0).getCorrelationID();
        String signatureValueCorrelationID = signatureValueSecurityEvent.getCorrelationID();
        String operationCorrelationID = operationSecurityEvent.getCorrelationID();

        List<SecurityEvent> operationSecurityEvents = new ArrayList<>();
        List<SecurityEvent> encryptedPartSecurityEvents = new ArrayList<>();
        List<SecurityEvent> signedElementSecurityEvents1 = new ArrayList<>();
        List<SecurityEvent> signatureValueSecurityEvents = new ArrayList<>();

        List<SecurityEvent> securityEvents = securityEventListener.getReceivedSecurityEvents();
        for (SecurityEvent securityEvent : securityEvents) {
            if (securityEvent.getCorrelationID().equals(encryptedPartCorrelationID)) {
                encryptedPartSecurityEvents.add(securityEvent);
            } else if (securityEvent.getCorrelationID().equals(signedElementCorrelationID1)) {
                signedElementSecurityEvents1.add(securityEvent);
            } else if (securityEvent.getCorrelationID().equals(signatureValueCorrelationID)) {
                signatureValueSecurityEvents.add(securityEvent);
            } else if (securityEvent.getCorrelationID().equals(operationCorrelationID)) {
                operationSecurityEvents.add(securityEvent);
            }
        }

        assertEquals(4, encryptedPartSecurityEvents.size());
        assertEquals(3, signedElementSecurityEvents1.size());
        assertEquals(4, signatureValueSecurityEvents.size());
        assertEquals(securityEventListener.getReceivedSecurityEvents().size(),
                operationSecurityEvents.size() +
                        encryptedPartSecurityEvents.size() +
                        signedElementSecurityEvents1.size() +
                        signatureValueSecurityEvents.size() +
                        1 //the timestamp
        );
    }

    @Test
    public void testInteroperabilityOutbound() throws Exception {

        WSSSecurityProperties securityProperties = new WSSSecurityProperties();
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());
        securityProperties.setEncryptionUser("receiver");
        securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        securityProperties.setSignatureUser("transmitter");
        securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        List<WSSConstants.Action> actions = new ArrayList<>();
        actions.add(WSSConstants.TIMESTAMP);
        actions.add(WSSConstants.SIGNATURE);
        actions.add(WSSConstants.ENCRYPTION);
        securityProperties.setActions(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(securityProperties, sourceDocument);

        String action = WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPTION;
        doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
    }

    @Test
    public void testInteroperabilityOutboundReverseOrder() throws Exception {

        WSSSecurityProperties securityProperties = new WSSSecurityProperties();
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());
        securityProperties.setEncryptionUser("receiver");
        securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        securityProperties.setSignatureUser("transmitter");
        securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        List<WSSConstants.Action> actions = new ArrayList<>();
        actions.add(WSSConstants.ENCRYPTION);
        actions.add(WSSConstants.SIGNATURE);
        actions.add(WSSConstants.TIMESTAMP);
        securityProperties.setActions(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(securityProperties, sourceDocument);

        String action = WSHandlerConstants.ENCRYPTION + " " + WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.TIMESTAMP;
        doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
    }

    @Test
    public void testInteroperabilityOutboundSignature() throws Exception {

        WSSSecurityProperties securityProperties = new WSSSecurityProperties();
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());
        securityProperties.setEncryptionUser("receiver");
        securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        securityProperties.setSignatureUser("transmitter");
        securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        List<WSSConstants.Action> actions = new ArrayList<>();
        actions.add(WSSConstants.SIGNATURE);
        securityProperties.setActions(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(securityProperties, sourceDocument);

        String action = WSHandlerConstants.SIGNATURE;
        doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
    }

    @Test
    public void testInteroperabilityInboundSecurityHeaderTimestampOrder() throws Exception {

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

        String action = WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPTION;
        Properties properties = new Properties();
        properties.setProperty(WSHandlerConstants.SIGNATURE_PARTS, "{Element}{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp;{Element}{http://schemas.xmlsoap.org/soap/envelope/}Body;");
        properties.setProperty(WSHandlerConstants.ENCRYPTION_PARTS, "{Element}{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp;{Content}{http://schemas.xmlsoap.org/soap/envelope/}Body;");
        Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
        transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));

        XPathExpression xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedData");
        Element timeStamp = (Element) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);
        Element securityHeaderNode = (Element) timeStamp.getParentNode();
        securityHeaderNode.removeChild(timeStamp);

        xPathExpression = getXPath("/soap:Envelope/soap:Header/wsse:Security/dsig:Signature");
        Element signature = (Element) xPathExpression.evaluate(securedDocument, XPathConstants.NODE);

        securityHeaderNode.insertBefore(timeStamp, signature);

        WSSSecurityProperties securityProperties = new WSSSecurityProperties();
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());
        securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        WSSecurityEventConstants.Event[] expectedSecurityEvents = new WSSecurityEventConstants.Event[]{
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.X509Token,
                WSSecurityEventConstants.X509Token,
                WSSecurityEventConstants.SignatureValue,
                WSSecurityEventConstants.EncryptedElement,
                WSSecurityEventConstants.TIMESTAMP,
                WSSecurityEventConstants.SignedElement,
                WSSecurityEventConstants.SIGNED_PART,
                WSSecurityEventConstants.ENCRYPTED_PART,
                WSSecurityEventConstants.OPERATION,
        };
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener(expectedSecurityEvents);
        Document document = doInboundSecurity(
                securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), securityEventListener);

        //read the whole stream:
        transformer = TRANSFORMER_FACTORY.newTransformer();
        transformer.transform(new DOMSource(document), new StreamResult(
                new OutputStream() {
                    @Override
                    public void write(int b) throws IOException {
                        // > /dev/null
                    }
                }
        ));
        securityEventListener.compare();

        EncryptedElementSecurityEvent encryptedElementSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.EncryptedElement);
        EncryptedPartSecurityEvent encryptedPartSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.ENCRYPTED_PART);
        List<SignedElementSecurityEvent> signedElementSecurityEvents = securityEventListener.getSecurityEvents(WSSecurityEventConstants.SignedElement);
        List<SignedPartSecurityEvent> signedPartSecurityEvents = securityEventListener.getSecurityEvents(WSSecurityEventConstants.SIGNED_PART);
        SignatureValueSecurityEvent signatureValueSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.SignatureValue);
        OperationSecurityEvent operationSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.OPERATION);
        String encryptedElementCorrelationID = encryptedElementSecurityEvent.getCorrelationID();
        String encryptedPartCorrelationID = encryptedPartSecurityEvent.getCorrelationID();
        String signedElementCorrelationID1 = signedElementSecurityEvents.get(0).getCorrelationID();
        String signedElementCorrelationID2 = signedPartSecurityEvents.get(0).getCorrelationID();
        String signatureValueCorrelationID = signatureValueSecurityEvent.getCorrelationID();
        String operationCorrelationID = operationSecurityEvent.getCorrelationID();

        List<SecurityEvent> operationSecurityEvents = new ArrayList<>();
        List<SecurityEvent> encryptedPartSecurityEvents = new ArrayList<>();
        List<SecurityEvent> encryptedElementSecurityEvents = new ArrayList<>();
        List<SecurityEvent> signedElementSecurityEvents1 = new ArrayList<>();
        List<SecurityEvent> signedElementSecurityEvents2 = new ArrayList<>();
        List<SecurityEvent> signatureValueSecurityEvents = new ArrayList<>();

        List<SecurityEvent> securityEvents = securityEventListener.getReceivedSecurityEvents();
        for (SecurityEvent securityEvent : securityEvents) {
            if (securityEvent.getCorrelationID().equals(encryptedPartCorrelationID)) {
                encryptedPartSecurityEvents.add(securityEvent);
            } else if (securityEvent.getCorrelationID().equals(encryptedElementCorrelationID)) {
                encryptedElementSecurityEvents.add(securityEvent);
            } else if (securityEvent.getCorrelationID().equals(signedElementCorrelationID1)) {
                signedElementSecurityEvents1.add(securityEvent);
            } else if (securityEvent.getCorrelationID().equals(signedElementCorrelationID2)) {
                signedElementSecurityEvents2.add(securityEvent);
            } else if (securityEvent.getCorrelationID().equals(signatureValueCorrelationID)) {
                signatureValueSecurityEvents.add(securityEvent);
            } else if (securityEvent.getCorrelationID().equals(operationCorrelationID)) {
                operationSecurityEvents.add(securityEvent);
            }
        }

        assertEquals(3, encryptedPartSecurityEvents.size());
        assertEquals(3, encryptedElementSecurityEvents.size());
        assertEquals(3, signedElementSecurityEvents1.size());
        assertEquals(3, signedElementSecurityEvents2.size());
        assertEquals(4, signatureValueSecurityEvents.size());
        assertEquals(securityEventListener.getReceivedSecurityEvents().size(),
                operationSecurityEvents.size() +
                        encryptedPartSecurityEvents.size() +
                        encryptedElementSecurityEvents.size() +
                        signedElementSecurityEvents1.size() +
                        signedElementSecurityEvents2.size() +
                        signatureValueSecurityEvents.size() +
                        1 //the timestamp
        );
    }

    @Test
    public void testEncDecryptionUseReqSigCert() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPTION;
            Properties properties = new Properties();
            properties.setProperty(WSHandlerConstants.SIGNATURE_PARTS, "{Element}{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp;{Element}{http://schemas.xmlsoap.org/soap/envelope/}Body;");
            Map<String, Object> messageContext = doOutboundSecurityWithWSS4J_1(sourceDocument, action, properties);
            Document securedDocument = (Document) messageContext.get(SECURED_DOCUMENT);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        final List<SecurityEvent> securityEventList = new ArrayList<>();
        //done signature; now test sig-verification:
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);

            SecurityEventListener securityEventListener = new SecurityEventListener() {
                @Override
                public void registerSecurityEvent(SecurityEvent securityEvent) throws WSSecurityException {
                    securityEventList.add(securityEvent);
                }
            };

            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), new ArrayList<SecurityEvent>(), securityEventListener);

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());
        }

        //so we have a request generated, now do the response:
        baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.TIMESTAMP);
            actions.add(WSSConstants.SIGNATURE);
            actions.add(WSSConstants.ENCRYPTION);
            securityProperties.setActions(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("receiver");
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.setUseReqSigCertForEncryption(true);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), securityEventList);
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Reference.getNamespaceURI(), WSSConstants.TAG_dsig_Reference.getLocalPart());
            assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.NS_SOAP11, WSSConstants.TAG_SOAP_BODY_LN);
            assertEquals(nodeList.getLength(), 1);
            String idAttrValue = ((Element) nodeList.item(0)).getAttributeNS(WSSConstants.ATT_WSU_ID.getNamespaceURI(), WSSConstants.ATT_WSU_ID.getLocalPart());
            assertNotNull(idAttrValue);
            assertTrue(idAttrValue.length() > 0);
        }

        //verify SigConf response:
        {
            String action = WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPTION;
            Properties properties = new Properties();
            doInboundSecurityWithWSS4J_1(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action, properties, true);
        }
    }

    @Test
    public void testEncryptedSignatureC14NInclusivePartsOutbound() throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.SIGNATURE);
            actions.add(WSSConstants.ENCRYPTION);
            securityProperties.setActions(actions);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setEncryptionUser("receiver");
            securityProperties.addSignaturePart(new SecurePart(new QName("http://www.w3.org/1999/XMLSchema", "complexType"), SecurePart.Modifier.Element));
            securityProperties.setSignatureCanonicalizationAlgorithm("http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments");
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Reference.getNamespaceURI(), WSSConstants.TAG_dsig_Reference.getLocalPart());
            assertEquals(nodeList.getLength(), 25);

            nodeList = document.getElementsByTagNameNS("http://www.w3.org/1999/XMLSchema", "complexType");
            assertEquals(nodeList.getLength(), 0);
        }

        //done signature; now test sig-verification:
        {
            String action = WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPTION;
            Properties properties = new Properties();
            doInboundSecurityWithWSS4J_1(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action, properties, false);
        }
    }

    /**
     * Inclusive Canonicalization with Encryption is problematic because xenc namespace "leaks"
     * WSS4J sets the xenc ns on the soap envelope which is not included in the signature on the sending
     * side. swsssf sets the ns where it belongs and so we don't have this problem. But if we
     * get an xenc ns on the envelope we will get a signature error. This case can't be handled correctly.
     * This is also one of the reasons why a exclusive canonicalisation is preferred for SOAP
     *
     * @throws Exception
     */
    @Test
    public void testSignatureC14NInclusivePartsInbound() throws Exception {
        //retest 100 times to make sure we don't have a threading issue
        for (int i = 0; i < 100; i++) {
            Document securedDocument;
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            {
                WSSSecurityProperties securityProperties = new WSSSecurityProperties();
                List<WSSConstants.Action> actions = new ArrayList<>();
                actions.add(WSSConstants.SIGNATURE);
                actions.add(WSSConstants.ENCRYPTION);
                securityProperties.setActions(actions);
                securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
                securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
                securityProperties.setSignatureUser("transmitter");
                securityProperties.setEncryptionUser("receiver");
                securityProperties.addSignaturePart(new SecurePart(new QName("http://www.w3.org/1999/XMLSchema", "complexType"), SecurePart.Modifier.Element));
                securityProperties.setSignatureCanonicalizationAlgorithm("http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments");
                securityProperties.setCallbackHandler(new CallbackHandlerImpl());

                OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
                XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
                XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
                XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
                xmlStreamWriter.close();

                securedDocument = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
                NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
                assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());
            }

            {
                String action = WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPTION;
                Properties properties = new Properties();
                doInboundSecurityWithWSS4J_1(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action, properties, false);
            }

            //done signature; now test sig-verification:
            {
                WSSSecurityProperties securityProperties = new WSSSecurityProperties();
                securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
                securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
                securityProperties.setCallbackHandler(new CallbackHandlerImpl());
                securityProperties.addIgnoreBSPRule(BSPRule.R5404);
                securityProperties.addIgnoreBSPRule(BSPRule.R5423);
                securityProperties.addIgnoreBSPRule(BSPRule.R5412);
                InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);

                WSSecurityEventConstants.Event[] expectedSecurityEvents = new WSSecurityEventConstants.Event[]{
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.X509Token,
                        WSSecurityEventConstants.X509Token,
                        WSSecurityEventConstants.SignatureValue,
                        WSSecurityEventConstants.ENCRYPTED_PART,
                        WSSecurityEventConstants.OPERATION,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.SignedElement,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.SignedElement,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.SignedElement,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.SignedElement,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.SignedElement,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.SignedElement,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.SignedElement,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.SignedElement,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.SignedElement,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.SignedElement,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.SignedElement,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.SignedElement,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.SignedElement,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.SignedElement,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.SignedElement,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.SignedElement,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.SignedElement,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.SignedElement,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.SignedElement,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.SignedElement,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.SignedElement,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.SignedElement,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.SignedElement,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.SignedElement,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.AlgorithmSuite,
                        WSSecurityEventConstants.SignedElement,
                };
                final TestSecurityEventListener securityEventListener = new TestSecurityEventListener(expectedSecurityEvents);
                XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(
                        xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), null, securityEventListener);

                Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

                //header element must still be there
                NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
                assertEquals(nodeList.getLength(), 1);
                assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

                securityEventListener.compare();
            }
        }
    }

    @Test
    public void testInteroperabilitySOAPActionInbound() throws Exception {

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

        String action = WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPTION;
        Properties properties = new Properties();
        properties.setProperty(WSHandlerConstants.SIGNATURE_PARTS, "{Element}{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp;{Element}{http://schemas.xmlsoap.org/soap/envelope/}Body;");
        properties.setProperty(WSHandlerConstants.ACTOR, "test");
        Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
        transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));

        WSSSecurityProperties securityProperties = new WSSSecurityProperties();
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());
        securityProperties.setActor("test");
        securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        WSSecurityEventConstants.Event[] expectedSecurityEvents = new WSSecurityEventConstants.Event[]{
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.X509Token,
                WSSecurityEventConstants.X509Token,
                WSSecurityEventConstants.SignatureValue,
                WSSecurityEventConstants.TIMESTAMP,
                WSSecurityEventConstants.SignedElement,
                WSSecurityEventConstants.SIGNED_PART,
                WSSecurityEventConstants.ENCRYPTED_PART,
                WSSecurityEventConstants.OPERATION,
        };
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener(expectedSecurityEvents);
        Document document = doInboundSecurity(
                securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), securityEventListener);

        //read the whole stream:
        transformer = TRANSFORMER_FACTORY.newTransformer();
        transformer.transform(new DOMSource(document), new StreamResult(
                new OutputStream() {
                    @Override
                    public void write(int b) throws IOException {
                        // > /dev/null
                    }
                }
        ));
        securityEventListener.compare();
    }

    @Test
    public void testInteroperabilityInvalidSOAPActionInbound() throws Exception {

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");

        String action = WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPTION;
        Properties properties = new Properties();
        properties.setProperty(WSHandlerConstants.SIGNATURE_PARTS, "{Element}{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp;{Element}{http://schemas.xmlsoap.org/soap/envelope/}Body;");
        properties.setProperty(WSHandlerConstants.ACTOR, "test");
        Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
        transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));

        WSSSecurityProperties securityProperties = new WSSSecurityProperties();
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());
        securityProperties.setActor("anotherTest");
        securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        WSSecurityEventConstants.Event[] expectedSecurityEvents = new WSSecurityEventConstants.Event[]{
                WSSecurityEventConstants.NO_SECURITY,
                WSSecurityEventConstants.OPERATION
        };
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener(expectedSecurityEvents);
        Document document = doInboundSecurity(
                securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), securityEventListener);

        //read the whole stream:
        transformer = TRANSFORMER_FACTORY.newTransformer();
        transformer.transform(new DOMSource(document), new StreamResult(
                new OutputStream() {
                    @Override
                    public void write(int b) throws IOException {
                        // > /dev/null
                    }
                }
        ));
        securityEventListener.compare();
    }

    @Test
    public void testInteroperabilitySOAPRoleInbound() throws Exception {

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.2.xml");

        String action = WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPTION;
        Properties properties = new Properties();
        properties.setProperty(WSHandlerConstants.ACTOR, "test");
        properties.setProperty(WSHandlerConstants.SIGNATURE_PARTS, "{Element}{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp;{Element}{http://www.w3.org/2003/05/soap-envelope}Body;");
        Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
        transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));

        WSSSecurityProperties securityProperties = new WSSSecurityProperties();
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());
        securityProperties.setActor("test");
        securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        WSSecurityEventConstants.Event[] expectedSecurityEvents = new WSSecurityEventConstants.Event[]{
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.AlgorithmSuite,
                WSSecurityEventConstants.X509Token,
                WSSecurityEventConstants.X509Token,
                WSSecurityEventConstants.SignatureValue,
                WSSecurityEventConstants.TIMESTAMP,
                WSSecurityEventConstants.SignedElement,
                WSSecurityEventConstants.SIGNED_PART,
                WSSecurityEventConstants.ENCRYPTED_PART,
                WSSecurityEventConstants.OPERATION,
        };
        final TestSecurityEventListener securityEventListener = new TestSecurityEventListener(expectedSecurityEvents);
        Document document = doInboundSecurity(
                securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), securityEventListener);

        //read the whole stream:
        transformer = TRANSFORMER_FACTORY.newTransformer();
        transformer.transform(new DOMSource(document), new StreamResult(
                new OutputStream() {
                    @Override
                    public void write(int b) throws IOException {
                        // > /dev/null
                    }
                }
        ));
        securityEventListener.compare();
    }

    @Test
    public void testInteroperabilityTwoSecurityHeadersSOAPRoleInbound() throws Exception {

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.2.xml");

        String action = WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPTION;
        Properties properties = new Properties();
        properties.setProperty(WSHandlerConstants.SIGNATURE_PARTS, "{Element}{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp;{Element}{http://www.w3.org/2003/05/soap-envelope}Body;");
        Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
        transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));

        properties.setProperty(WSHandlerConstants.ACTOR, "test");
        securedDocument = doOutboundSecurityWithWSS4J(new ByteArrayInputStream(baos.toByteArray()), action, properties);

        transformer = TRANSFORMER_FACTORY.newTransformer();
        baos.reset();
        transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));

        WSSSecurityProperties securityProperties = new WSSSecurityProperties();
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());
        securityProperties.setActor("test");
        securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

        Document document = doInboundSecurity(securityProperties, xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

        //read the whole stream:
        transformer = TRANSFORMER_FACTORY.newTransformer();
        transformer.transform(new DOMSource(document), new StreamResult(
                new OutputStream() {
                    @Override
                    public void write(int b) throws IOException {
                        // > /dev/null
                    }
                }
        ));
    }

    @Test
    public void testInteroperabilitySOAPActionOutbound() throws Exception {

        WSSSecurityProperties securityProperties = new WSSSecurityProperties();
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());
        securityProperties.setActor("test");
        securityProperties.setEncryptionUser("receiver");
        securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        securityProperties.setSignatureUser("transmitter");
        securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        List<WSSConstants.Action> actions = new ArrayList<>();
        actions.add(WSSConstants.TIMESTAMP);
        actions.add(WSSConstants.SIGNATURE);
        actions.add(WSSConstants.ENCRYPTION);
        securityProperties.setActions(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(securityProperties, sourceDocument);

        String action = WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPTION;
        Properties properties = new Properties();
        properties.setProperty(WSHandlerConstants.ACTOR, "test");
        doInboundSecurityWithWSS4J_1(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action, properties, false);
    }

    @Test
    public void testInteroperabilityInvalidSOAPActionOutbound() throws Exception {

        WSSSecurityProperties securityProperties = new WSSSecurityProperties();
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());
        securityProperties.setActor("test");
        securityProperties.setEncryptionUser("receiver");
        securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        securityProperties.setSignatureUser("transmitter");
        securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        List<WSSConstants.Action> actions = new ArrayList<>();
        actions.add(WSSConstants.TIMESTAMP);
        actions.add(WSSConstants.SIGNATURE);
        actions.add(WSSConstants.ENCRYPTION);
        securityProperties.setActions(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(securityProperties, sourceDocument);

        String action = WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPTION;
        Properties properties = new Properties();
        properties.setProperty(WSHandlerConstants.ACTOR, "anotherTest");
        try {
            doInboundSecurityWithWSS4J_1(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action, properties, false);
            fail("Expected WSSecurityException");
        } catch (WSSecurityException e) {
            assertEquals(e.getMessage(), "WSS4JHandler: Request does not contain required Security header");
        }
    }

    @Test
    public void testInteroperabilitySOAPRoleOutbound() throws Exception {

        WSSSecurityProperties securityProperties = new WSSSecurityProperties();
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());
        securityProperties.setActor("test");
        securityProperties.setEncryptionUser("receiver");
        securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        securityProperties.setSignatureUser("transmitter");
        securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        List<WSSConstants.Action> actions = new ArrayList<>();
        actions.add(WSSConstants.TIMESTAMP);
        actions.add(WSSConstants.SIGNATURE);
        actions.add(WSSConstants.ENCRYPTION);
        securityProperties.setActions(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.2.xml");

        ByteArrayOutputStream baos = doOutboundSecurity(securityProperties, sourceDocument);

        String action = WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPTION;
        Properties properties = new Properties();
        properties.setProperty(WSHandlerConstants.ACTOR, "test");
        doInboundSecurityWithWSS4J_1(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action, properties, false);
    }

    @Test
    public void testInteroperabilityTwoSecurityHeadersSOAPRoleOutbound() throws Exception {

        WSSSecurityProperties securityProperties = new WSSSecurityProperties();
        securityProperties.setCallbackHandler(new CallbackHandlerImpl());
        securityProperties.setEncryptionUser("receiver");
        securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        securityProperties.setSignatureUser("transmitter");
        securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        List<WSSConstants.Action> actions = new ArrayList<>();
        actions.add(WSSConstants.TIMESTAMP);
        actions.add(WSSConstants.SIGNATURE);
        actions.add(WSSConstants.ENCRYPTION);
        securityProperties.setActions(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.2.xml");

        ByteArrayOutputStream baos = doOutboundSecurity(securityProperties, sourceDocument);

        securityProperties.setActor("test");
        baos = doOutboundSecurity(securityProperties, new ByteArrayInputStream(baos.toByteArray()));

        String action = WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPTION;
        Properties properties = new Properties();
        properties.setProperty(WSHandlerConstants.ACTOR, "test");
        doInboundSecurityWithWSS4J_1(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action, properties, false);
    }

    @Test
    public void testInvalidXML() throws Exception {

        int i = 0;
        int e = 10000;

        while (i < e) {

            String action = WSHandlerConstants.USERNAME_TOKEN + " " + WSHandlerConstants.TIMESTAMP + " " + WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPTION;
            Properties properties = new Properties();
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            if (i == 0) {
                i = indexOfNode(securedDocument.getDocumentElement(), new NodeIndex(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart()).index;
                e = indexOfNode(securedDocument.getDocumentElement(), new NodeIndex(), "definitions").index;
            }
            i++;
            Node nodeToRemove = nodeOnIndex(securedDocument.getDocumentElement(), new NodeIndex(), i).node;
            if (nodeToRemove.getNodeType() == Node.ATTRIBUTE_NODE) {
                ((Attr) nodeToRemove).getOwnerElement().removeAttributeNode((Attr) nodeToRemove);
            } else {
                Node parentNode = nodeToRemove.getParentNode();
                parentNode.removeChild(nodeToRemove);
            }

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));

            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            Iterator<BSPRule> bspRules = EnumSet.allOf(BSPRule.class).iterator();
            while (bspRules.hasNext()) {
                securityProperties.addIgnoreBSPRule(bspRules.next());
            }

            try {
                Document document = doInboundSecurity(securityProperties,
                        xmlInputFactory.createXMLStreamReader(
                                new ByteArrayInputStream(baos.toByteArray())));

                //read the whole stream:
                transformer = TRANSFORMER_FACTORY.newTransformer();
                transformer.transform(new DOMSource(document), new StreamResult(
                        new OutputStream() {
                            @Override
                            public void write(int b) throws IOException {
                                // > /dev/null
                            }
                        }
                ));
            } catch (XMLStreamException ex) {
                int k = 0;
                Throwable t = ex.getCause();
                while (t != null && k < 100) {
                    StringWriter stringWriter = new StringWriter();
                    PrintWriter pw = new PrintWriter(stringWriter);
                    ex.printStackTrace(pw);
                    assertFalse(t instanceof NullPointerException, stringWriter.toString());
                    t = t.getCause();
                }
            }
        }
    }

    private NodeIndex indexOfNode(Node node, NodeIndex index, String name) {
        if (node.getLocalName() != null && node.getLocalName().equals(name)) {
            return index;
        }
        index.index++;
        if (node.getNodeType() == Node.ELEMENT_NODE) {
            NamedNodeMap namedNodeMap = node.getAttributes();
            for (int i = 0; i < namedNodeMap.getLength(); i++) {
                NodeIndex n = indexOfNode(namedNodeMap.item(i), index, name);
                if (n != null) {
                    return n;
                }
            }
        }
        NodeList nodeList = node.getChildNodes();
        for (int i = 0; i < nodeList.getLength(); i++) {
            NodeIndex n = indexOfNode(nodeList.item(i), index, name);
            if (n != null) {
                return n;
            }
        }
        return null;
    }

    private NodeIndex nodeOnIndex(Node node, NodeIndex index, int indexToFind) {
        if (index.index == indexToFind) {
            index.node = node;
            return index;
        }
        index.index++;
        if (node.getNodeType() == Node.ELEMENT_NODE) {
            NamedNodeMap namedNodeMap = node.getAttributes();
            for (int i = 0; i < namedNodeMap.getLength(); i++) {
                NodeIndex n = nodeOnIndex(namedNodeMap.item(i), index, indexToFind);
                if (n != null) {
                    return n;
                }
            }
        }
        NodeList nodeList = node.getChildNodes();
        for (int i = 0; i < nodeList.getLength(); i++) {
            NodeIndex n = nodeOnIndex(nodeList.item(i), index, indexToFind);
            if (n != null) {
                return n;
            }
        }
        return null;
    }

    class NodeIndex {
        Node node;
        int index;
    }
}