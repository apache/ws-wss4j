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
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.derivedKey.ConversationConstants;
import org.apache.wss4j.common.token.SecurityTokenReference;
import org.apache.wss4j.common.util.KeyUtils;
import org.apache.wss4j.common.util.SOAPUtil;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.dom.message.WSSecDKEncrypt;
import org.apache.wss4j.dom.message.WSSecDKSign;
import org.apache.wss4j.dom.message.WSSecEncryptedKey;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecSecurityContextToken;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.securityEvent.EncryptedPartSecurityEvent;
import org.apache.wss4j.stax.securityEvent.OperationSecurityEvent;
import org.apache.wss4j.stax.securityEvent.SignedPartSecurityEvent;
import org.apache.wss4j.stax.securityEvent.WSSecurityEventConstants;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.wss4j.stax.setup.InboundWSSec;
import org.apache.wss4j.stax.setup.OutboundWSSec;
import org.apache.wss4j.stax.setup.WSSec;
import org.apache.wss4j.stax.test.utils.StAX2DOM;
import org.apache.wss4j.stax.test.utils.XmlReaderToWriter;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEventConstants;
import org.apache.xml.security.stax.securityEvent.SignatureValueSecurityEvent;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class DerivedKeyTokenTest extends AbstractTestBase {

    @BeforeAll
    public static void setUp() throws Exception {
        WSSConfig.init();
    }

    @ParameterizedTest
    @ValueSource(ints = {ConversationConstants.VERSION_05_02, ConversationConstants.VERSION_05_12})
    public void testEncryptionDecryptionTRIPLEDESOutbound(int version) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.ENCRYPTION_WITH_DERIVED_KEY);
            securityProperties.setActions(actions);
            byte[] secret = WSSConstants.generateBytes(192 / 8);
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl(secret);
            securityProperties.setCallbackHandler(callbackHandler);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#tripledes-cbc");
            securityProperties.setEncryptionKeyIdentifier(WSSecurityTokenConstants.KEYIDENTIFIER_THUMBPRINT_IDENTIFIER);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_SOAP11_BODY.getLocalPart());
        }
        {
            String action = WSHandlerConstants.ENCRYPTION;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {ConversationConstants.VERSION_05_02, ConversationConstants.VERSION_05_12})
    public void testEncryptionDecryptionOutboundDeprecatedTag(int version) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.ENCRYPT_WITH_DERIVED_KEY);
            securityProperties.setActions(actions);
            byte[] secret = WSSConstants.generateBytes(192 / 8);
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl(secret);
            securityProperties.setCallbackHandler(callbackHandler);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionKeyIdentifier(WSSecurityTokenConstants.KEYIDENTIFIER_THUMBPRINT_IDENTIFIER);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_SOAP11_BODY.getLocalPart());
        }
        {
            String action = WSHandlerConstants.ENCRYPTION;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {ConversationConstants.VERSION_05_02, ConversationConstants.VERSION_05_12})
    public void testEncryptionDecryptionTRIPLEDESInbound(int version) throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
            WSSecHeader secHeader = new WSSecHeader(doc);
            secHeader.insertSecurityHeader();

            WSSecSecurityContextToken sctBuilder = new WSSecSecurityContextToken(secHeader, null);
            Crypto crypto = CryptoFactory.getInstance("transmitter-crypto.properties");
            sctBuilder.setWscVersion(version);
            sctBuilder.prepare(crypto);

            //EncryptedKey
            WSSecEncryptedKey encrKeyBuilder = new WSSecEncryptedKey(secHeader);
            encrKeyBuilder.setUserInfo("receiver");
            encrKeyBuilder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
            KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.AES_128);
            SecretKey symmetricKey = keyGen.generateKey();
            encrKeyBuilder.prepare(crypto, symmetricKey);

            //Key information from the EncryptedKey
            byte[] ek = symmetricKey.getEncoded();
            String tokenIdentifier = encrKeyBuilder.getId();

            //Derived key encryption
            WSSecDKEncrypt encrBuilder = new WSSecDKEncrypt(secHeader);
            encrBuilder.setWscVersion(version);
            encrBuilder.setSymmetricEncAlgorithm(WSConstants.TRIPLE_DES);
            encrBuilder.setTokenIdentifier(tokenIdentifier);
            encrBuilder.build(ek);

            encrKeyBuilder.prependToHeader();
            encrKeyBuilder.prependBSTElementToHeader();

            NodeList nodeList = doc.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 1);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(doc), new StreamResult(baos));
        }

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);

            SecurityEventConstants.Event[] expectedSecurityEvents = new SecurityEventConstants.Event[]{
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.X509Token,
                    WSSecurityEventConstants.ENCRYPTED_PART,
                    WSSecurityEventConstants.OPERATION,
            };
            final TestSecurityEventListener securityEventListener = new TestSecurityEventListener(expectedSecurityEvents);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(
                    xmlInputFactory.createXMLStreamReader(
                            new ByteArrayInputStream(baos.toByteArray())), null, securityEventListener);

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 0);

            securityEventListener.compare();

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

            assertEquals(6, encryptedPartSecurityEvents.size());
            assertEquals(1, operationSecurityEvents.size());
            assertEquals(securityEventListener.getReceivedSecurityEvents().size(), operationSecurityEvents.size() + encryptedPartSecurityEvents.size());
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {ConversationConstants.VERSION_05_02, ConversationConstants.VERSION_05_12})
    public void testEncryptionDecryptionTRIPLEDESInboundAction(int version) throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.ENCRYPTION_DERIVED;

            Properties properties = new Properties();
            properties.put(WSHandlerConstants.DERIVED_TOKEN_REFERENCE, "EncryptedKey");
            if (version == ConversationConstants.VERSION_05_02) {
                properties.put(WSHandlerConstants.USE_2005_12_NAMESPACE, "false");
            }
            properties.put(WSHandlerConstants.USER, "receiver");
            properties.put(WSHandlerConstants.ENC_SYM_ALGO,
                           "http://www.w3.org/2001/04/xmlenc#tripledes-cbc");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_SOAP11_BODY.getLocalPart());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);

            SecurityEventConstants.Event[] expectedSecurityEvents = new SecurityEventConstants.Event[]{
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.X509Token,
                    WSSecurityEventConstants.ENCRYPTED_PART,
                    WSSecurityEventConstants.OPERATION,
            };
            final TestSecurityEventListener securityEventListener = new TestSecurityEventListener(expectedSecurityEvents);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(
                    xmlInputFactory.createXMLStreamReader(
                            new ByteArrayInputStream(baos.toByteArray())), null, securityEventListener);

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 0);

            securityEventListener.compare();

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

            assertEquals(6, encryptedPartSecurityEvents.size());
            assertEquals(1, operationSecurityEvents.size());
            assertEquals(securityEventListener.getReceivedSecurityEvents().size(), operationSecurityEvents.size() + encryptedPartSecurityEvents.size());
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {ConversationConstants.VERSION_05_02, ConversationConstants.VERSION_05_12})
    public void testEncryptionDecryptionAES128Outbound(int version) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.ENCRYPTION_WITH_DERIVED_KEY);
            securityProperties.setActions(actions);
            byte[] secret = WSSConstants.generateBytes(128 / 8);
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl(secret);
            securityProperties.setCallbackHandler(callbackHandler);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#aes128-cbc");
            securityProperties.setEncryptionKeyIdentifier(WSSecurityTokenConstants.KEYIDENTIFIER_THUMBPRINT_IDENTIFIER);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_SOAP11_BODY.getLocalPart());
        }
        {
            String action = WSHandlerConstants.ENCRYPTION;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {ConversationConstants.VERSION_05_02, ConversationConstants.VERSION_05_12})
    public void testEncryptionDecryptionAES128Inbound(int version) throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
            WSSecHeader secHeader = new WSSecHeader(doc);
            secHeader.insertSecurityHeader();

            WSSecSecurityContextToken sctBuilder = new WSSecSecurityContextToken(secHeader, null);
            sctBuilder.setWscVersion(version);
            Crypto crypto = CryptoFactory.getInstance("transmitter-crypto.properties");
            sctBuilder.prepare(crypto);

            //EncryptedKey
            WSSecEncryptedKey encrKeyBuilder = new WSSecEncryptedKey(secHeader);
            encrKeyBuilder.setUserInfo("receiver");
            encrKeyBuilder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
            KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.AES_128);
            SecretKey symmetricKey = keyGen.generateKey();
            encrKeyBuilder.prepare(crypto, symmetricKey);

            //Key information from the EncryptedKey
            byte[] ek = symmetricKey.getEncoded();
            String tokenIdentifier = encrKeyBuilder.getId();

            //Derived key encryption
            WSSecDKEncrypt encrBuilder = new WSSecDKEncrypt(secHeader);
            encrBuilder.setWscVersion(version);
            encrBuilder.setSymmetricEncAlgorithm(WSConstants.AES_128);
            encrBuilder.setTokenIdentifier(tokenIdentifier);
            encrBuilder.build(ek);

            encrKeyBuilder.prependToHeader();
            encrKeyBuilder.prependBSTElementToHeader();

            NodeList nodeList = doc.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 1);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(doc), new StreamResult(baos));
        }
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 0);
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {ConversationConstants.VERSION_05_02, ConversationConstants.VERSION_05_12})
    public void testEncryptionDecryptionAES128InboundAction(int version) throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.ENCRYPTION_DERIVED;

            Properties properties = new Properties();
            properties.put(WSHandlerConstants.DERIVED_TOKEN_REFERENCE, "EncryptedKey");
            if (version == ConversationConstants.VERSION_05_02) {
                properties.put(WSHandlerConstants.USE_2005_12_NAMESPACE, "false");
            }
            properties.put(WSHandlerConstants.USER, "receiver");
            properties.put(WSHandlerConstants.ENC_SYM_ALGO,
                           "http://www.w3.org/2001/04/xmlenc#aes128-cbc");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_SOAP11_BODY.getLocalPart());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 0);
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {ConversationConstants.VERSION_05_02, ConversationConstants.VERSION_05_12})
    public void testSignatureOutbound() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.SIGNATURE_WITH_DERIVED_KEY);
            securityProperties.setActions(actions);
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl();
            securityProperties.setCallbackHandler(callbackHandler);
            securityProperties.setEncryptionKeyIdentifier(WSSecurityTokenConstants.KEYIDENTIFIER_THUMBPRINT_IDENTIFIER);
            securityProperties.setSignatureAlgorithm("http://www.w3.org/2000/09/xmldsig#hmac-sha1");
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setDerivedKeyTokenReference(WSSConstants.DerivedKeyTokenReference.EncryptedKey);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("receiver");

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());
        }
        {
            String action = WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPTION;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {ConversationConstants.VERSION_05_02, ConversationConstants.VERSION_05_12})
    public void testSignatureInbound(int version) throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
            WSSecHeader secHeader = new WSSecHeader(doc);
            secHeader.insertSecurityHeader();

            //EncryptedKey
            WSSecEncryptedKey encrKeyBuilder = new WSSecEncryptedKey(secHeader);
            encrKeyBuilder.setUserInfo("receiver");
            encrKeyBuilder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
            Crypto crypto = CryptoFactory.getInstance("transmitter-crypto.properties");

            KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.AES_128);
            SecretKey symmetricKey = keyGen.generateKey();
            encrKeyBuilder.prepare(crypto, symmetricKey);

            //Key information from the EncryptedKey
            byte[] ek = symmetricKey.getEncoded();
            String tokenIdentifier = encrKeyBuilder.getId();

            //Derived key encryption
            WSSecDKSign sigBuilder = new WSSecDKSign(secHeader);
            sigBuilder.setWscVersion(version);
            sigBuilder.setTokenIdentifier(tokenIdentifier);
            sigBuilder.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
            sigBuilder.build(ek);

            encrKeyBuilder.prependToHeader();
            encrKeyBuilder.prependBSTElementToHeader();

            NodeList nodeList = doc.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            assertEquals(nodeList.getLength(), 1);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(doc), new StreamResult(baos));
        }

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {ConversationConstants.VERSION_05_02, ConversationConstants.VERSION_05_12})
    public void testSignatureInboundAction(int version) throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SIGNATURE_DERIVED;

            Properties properties = new Properties();
            properties.put(WSHandlerConstants.DERIVED_TOKEN_REFERENCE, "EncryptedKey");
            if (version == ConversationConstants.VERSION_05_02) {
                properties.put(WSHandlerConstants.USE_2005_12_NAMESPACE, "false");
            }
            properties.put(WSHandlerConstants.USER, "receiver");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {ConversationConstants.VERSION_05_02, ConversationConstants.VERSION_05_12})
    public void testSignatureThumbprintSHA1Outbound(int version) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.SIGNATURE_WITH_DERIVED_KEY);
            securityProperties.setActions(actions);
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl();
            securityProperties.setCallbackHandler(callbackHandler);
            securityProperties.setSignatureAlgorithm("http://www.w3.org/2000/09/xmldsig#hmac-sha1");
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("receiver");
            securityProperties.setDerivedKeyTokenReference(WSSConstants.DerivedKeyTokenReference.DirectReference);
            securityProperties.setDerivedKeyKeyIdentifier(WSSecurityTokenConstants.KEYIDENTIFIER_THUMBPRINT_IDENTIFIER);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_WSC0512_SCT.getNamespaceURI(), WSSConstants.TAG_WSC0512_SCT.getLocalPart());
            assertEquals(nodeList.getLength(), 0);
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.getLength(), 0);
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_WSC0512_DKT.getNamespaceURI(), WSSConstants.TAG_WSC0512_DKT.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_WSSE_KEY_IDENTIFIER.getNamespaceURI(), WSSConstants.TAG_WSSE_KEY_IDENTIFIER.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
            Attr attr = (Attr) nodeList.item(0).getAttributes().getNamedItem(WSSConstants.ATT_NULL_VALUE_TYPE.getLocalPart());
            assertEquals(attr.getValue(), WSSConstants.NS_THUMBPRINT);
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
        }
        {
            String action = WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPTION;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {ConversationConstants.VERSION_05_02, ConversationConstants.VERSION_05_12})
    public void testSignatureThumbprintSHA1Inbound(int version) throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
            WSSecHeader secHeader = new WSSecHeader(doc);
            secHeader.insertSecurityHeader();

            SecurityTokenReference secToken = new SecurityTokenReference(doc);
            CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
            cryptoType.setAlias("transmitter");
            Crypto crypto = CryptoFactory.getInstance("transmitter-crypto.properties");
            X509Certificate[] certs = crypto.getX509Certificates(cryptoType);
            secToken.setKeyIdentifierThumb(certs[0]);

            WSSecDKSign sigBuilder = new WSSecDKSign(secHeader);
            sigBuilder.setWscVersion(version);
            java.security.Key key = crypto.getPrivateKey("transmitter", "default");
            sigBuilder.setStrElem(secToken.getElement());
            sigBuilder.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
            sigBuilder.build(key.getEncoded());

            sigBuilder.prependDKElementToHeader();

            NodeList nodeList = doc.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            assertEquals(nodeList.getLength(), 1);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(doc), new StreamResult(baos));
        }

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
        }
    }


    @ParameterizedTest
    @ValueSource(ints = {ConversationConstants.VERSION_05_02, ConversationConstants.VERSION_05_12})
    public void testSignatureThumbprintSHA1InboundAction(int version) throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SIGNATURE_DERIVED;

            Properties properties = new Properties();
            properties.put(WSHandlerConstants.DERIVED_TOKEN_REFERENCE, "DirectReference");
            if (version == ConversationConstants.VERSION_05_02) {
                properties.put(WSHandlerConstants.USE_2005_12_NAMESPACE, "false");
            }
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {ConversationConstants.VERSION_05_02, ConversationConstants.VERSION_05_12})
    public void testSignatureSKIOutbound() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.SIGNATURE_WITH_DERIVED_KEY);
            securityProperties.setActions(actions);
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl();
            securityProperties.setCallbackHandler(callbackHandler);
            securityProperties.setSignatureAlgorithm("http://www.w3.org/2000/09/xmldsig#hmac-sha1");
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("receiver");
            securityProperties.setDerivedKeyTokenReference(WSSConstants.DerivedKeyTokenReference.DirectReference);
            securityProperties.setDerivedKeyKeyIdentifier(WSSecurityTokenConstants.KeyIdentifier_SkiKeyIdentifier);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_WSC0512_SCT.getNamespaceURI(), WSSConstants.TAG_WSC0512_SCT.getLocalPart());
            assertEquals(nodeList.getLength(), 0);
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.getLength(), 0);
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_WSC0512_DKT.getNamespaceURI(), WSSConstants.TAG_WSC0512_DKT.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_WSSE_KEY_IDENTIFIER.getNamespaceURI(), WSSConstants.TAG_WSSE_KEY_IDENTIFIER.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
            Attr attr = (Attr) nodeList.item(0).getAttributes().getNamedItem(WSSConstants.ATT_NULL_VALUE_TYPE.getLocalPart());
            assertEquals(attr.getValue(), WSSConstants.NS_X509_SKI);
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
        }
        {
            String action = WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPTION;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {ConversationConstants.VERSION_05_02, ConversationConstants.VERSION_05_12})
    public void testSignatureSKIInbound(int version) throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
            WSSecHeader secHeader = new WSSecHeader(doc);
            secHeader.insertSecurityHeader();

            SecurityTokenReference secToken = new SecurityTokenReference(doc);
            CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
            cryptoType.setAlias("transmitter");
            Crypto crypto = CryptoFactory.getInstance("transmitter-crypto.properties");
            X509Certificate[] certs = crypto.getX509Certificates(cryptoType);
            secToken.setKeyIdentifierSKI(certs[0], crypto);

            WSSecDKSign sigBuilder = new WSSecDKSign(secHeader);
            sigBuilder.setWscVersion(version);
            java.security.Key key = crypto.getPrivateKey("transmitter", "default");
            sigBuilder.setStrElem(secToken.getElement());
            sigBuilder.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
            sigBuilder.build(key.getEncoded());

            sigBuilder.prependDKElementToHeader();

            NodeList nodeList = doc.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            assertEquals(nodeList.getLength(), 1);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(doc), new StreamResult(baos));
        }

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {ConversationConstants.VERSION_05_02, ConversationConstants.VERSION_05_12})
    public void testSignatureSKIInboundAction(int version) throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SIGNATURE_DERIVED;

            Properties properties = new Properties();
            properties.put(WSHandlerConstants.DERIVED_TOKEN_REFERENCE, "DirectReference");
            properties.put(WSHandlerConstants.DERIVED_TOKEN_KEY_ID, "SKIKeyIdentifier");
            if (version == ConversationConstants.VERSION_05_02) {
                properties.put(WSHandlerConstants.USE_2005_12_NAMESPACE, "false");
            }
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {ConversationConstants.VERSION_05_02, ConversationConstants.VERSION_05_12})
    public void testSignatureEncryptOutbound(int version) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.SIGNATURE_WITH_DERIVED_KEY);
            actions.add(WSSConstants.ENCRYPTION_WITH_DERIVED_KEY);
            securityProperties.setActions(actions);
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl();
            securityProperties.setCallbackHandler(callbackHandler);
            securityProperties.setSignatureAlgorithm("http://www.w3.org/2000/09/xmldsig#hmac-sha1");
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("receiver");
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionKeyIdentifier(WSSecurityTokenConstants.KEYIDENTIFIER_THUMBPRINT_IDENTIFIER);
            securityProperties.setDerivedKeyTokenReference(WSSConstants.DerivedKeyTokenReference.EncryptedKey);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_WSC0512_SCT.getNamespaceURI(), WSSConstants.TAG_WSC0512_SCT.getLocalPart());
            assertEquals(nodeList.getLength(), 0);
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_WSC0512_DKT.getNamespaceURI(), WSSConstants.TAG_WSC0512_DKT.getLocalPart());
            assertEquals(nodeList.getLength(), 2);
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
        }
        {
            String action = WSHandlerConstants.SIGNATURE + " " + WSHandlerConstants.ENCRYPTION;
            doInboundSecurityWithWSS4J(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action);
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {ConversationConstants.VERSION_05_02, ConversationConstants.VERSION_05_12})
    public void testSignatureEncryptInbound(int version) throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
            WSSecHeader secHeader = new WSSecHeader(doc);
            secHeader.insertSecurityHeader();

            Crypto crypto = CryptoFactory.getInstance("transmitter-crypto.properties");

            //EncryptedKey
            WSSecEncryptedKey encrKeyBuilder = new WSSecEncryptedKey(secHeader);
            encrKeyBuilder.setUserInfo("receiver");
            encrKeyBuilder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);

            KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.AES_128);
            SecretKey symmetricKey = keyGen.generateKey();
            encrKeyBuilder.prepare(crypto, symmetricKey);

            //Key information from the EncryptedKey
            byte[] ek = symmetricKey.getEncoded();
            String tokenIdentifier = encrKeyBuilder.getId();

            //Derived key encryption
            WSSecDKSign sigBuilder = new WSSecDKSign(secHeader);
            sigBuilder.setWscVersion(version);
            sigBuilder.setTokenIdentifier(tokenIdentifier);
            sigBuilder.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
            sigBuilder.build(ek);

            //Derived key signature
            WSSecDKEncrypt encrBuilder = new WSSecDKEncrypt(secHeader);
            encrBuilder.setWscVersion(version);
            encrBuilder.setSymmetricEncAlgorithm(WSConstants.AES_128);
            encrBuilder.setTokenIdentifier(tokenIdentifier);
            encrBuilder.build(ek);

            encrKeyBuilder.prependToHeader();
            encrKeyBuilder.prependBSTElementToHeader();

            NodeList nodeList = doc.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            assertEquals(nodeList.getLength(), 1);

            nodeList = doc.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 1);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(doc), new StreamResult(baos));
        }

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);

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
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.X509Token,
                    WSSecurityEventConstants.SignatureValue,
                    WSSecurityEventConstants.SIGNED_PART,
                    WSSecurityEventConstants.ENCRYPTED_PART,
                    WSSecurityEventConstants.OPERATION,
            };
            final TestSecurityEventListener securityEventListener = new TestSecurityEventListener(expectedSecurityEvents);

            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), null, securityEventListener);

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 0);

            securityEventListener.compare();

            EncryptedPartSecurityEvent encryptedPartSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.ENCRYPTED_PART);
            SignedPartSecurityEvent signedPartSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.SIGNED_PART);
            SignatureValueSecurityEvent signatureValueSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.SignatureValue);
            OperationSecurityEvent operationSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.OPERATION);
            String encryptedPartCorrelationID = encryptedPartSecurityEvent.getCorrelationID();
            String signedElementCorrelationID = signedPartSecurityEvent.getCorrelationID();
            String signatureValueCorrelationID = signatureValueSecurityEvent.getCorrelationID();
            String operationCorrelationID = operationSecurityEvent.getCorrelationID();

            List<SecurityEvent> operationSecurityEvents = new ArrayList<>();
            List<SecurityEvent> encryptedPartSecurityEvents = new ArrayList<>();
            List<SecurityEvent> signedElementSecurityEvents = new ArrayList<>();
            List<SecurityEvent> signatureValueSecurityEvents = new ArrayList<>();

            List<SecurityEvent> securityEvents = securityEventListener.getReceivedSecurityEvents();
            for (int i = 0; i < securityEvents.size(); i++) {
                SecurityEvent securityEvent = securityEvents.get(i);
                if (securityEvent.getCorrelationID().equals(encryptedPartCorrelationID)) {
                    encryptedPartSecurityEvents.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(operationCorrelationID)) {
                    operationSecurityEvents.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(signedElementCorrelationID)) {
                    signedElementSecurityEvents.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(signatureValueCorrelationID)) {
                    signatureValueSecurityEvents.add(securityEvent);
                }
            }

            assertEquals(5, encryptedPartSecurityEvents.size());
            assertEquals(3, signedElementSecurityEvents.size());
            assertEquals(6, signatureValueSecurityEvents.size());
            assertEquals(securityEventListener.getReceivedSecurityEvents().size(),
                    operationSecurityEvents.size() + encryptedPartSecurityEvents.size() +
                            signedElementSecurityEvents.size() + signatureValueSecurityEvents.size());
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {ConversationConstants.VERSION_05_02, ConversationConstants.VERSION_05_12})
    public void testEncryptSignatureInbound(int version) throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
            WSSecHeader secHeader = new WSSecHeader(doc);
            secHeader.insertSecurityHeader();

            Crypto crypto = CryptoFactory.getInstance("transmitter-crypto.properties");

            //EncryptedKey
            WSSecEncryptedKey encrKeyBuilder = new WSSecEncryptedKey(secHeader);
            encrKeyBuilder.setUserInfo("receiver");
            encrKeyBuilder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);

            KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.AES_128);
            SecretKey symmetricKey = keyGen.generateKey();
            encrKeyBuilder.prepare(crypto, symmetricKey);

            //Key information from the EncryptedKey
            byte[] ek = symmetricKey.getEncoded();
            String tokenIdentifier = encrKeyBuilder.getId();

            //Derived key signature
            WSSecDKEncrypt encrBuilder = new WSSecDKEncrypt(secHeader);
            encrBuilder.setWscVersion(version);
            encrBuilder.setSymmetricEncAlgorithm(WSConstants.AES_128);
            encrBuilder.setTokenIdentifier(tokenIdentifier);
            encrBuilder.build(ek);

            //Derived key encryption
            WSSecDKSign sigBuilder = new WSSecDKSign(secHeader);
            sigBuilder.setWscVersion(version);
            sigBuilder.setTokenIdentifier(tokenIdentifier);
            sigBuilder.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
            sigBuilder.build(ek);

            encrKeyBuilder.prependToHeader();
            encrKeyBuilder.prependBSTElementToHeader();

            NodeList nodeList = doc.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            assertEquals(nodeList.getLength(), 1);

            nodeList = doc.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 1);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(doc), new StreamResult(baos));
        }

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 0);
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {ConversationConstants.VERSION_05_02, ConversationConstants.VERSION_05_12})
    public void testEncryptSignatureInboundAction(int version) throws Exception {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SIGNATURE_DERIVED + " " + WSHandlerConstants.ENCRYPTION_DERIVED;

            Properties properties = new Properties();
            properties.put(WSHandlerConstants.DERIVED_TOKEN_REFERENCE, "EncryptedKey");
            if (version == ConversationConstants.VERSION_05_02) {
                properties.put(WSHandlerConstants.USE_2005_12_NAMESPACE, "false");
            }
            properties.put(WSHandlerConstants.USER, "receiver");
            properties.put(WSHandlerConstants.SIG_ALGO,
                           "http://www.w3.org/2000/09/xmldsig#hmac-sha1");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_SOAP11_BODY.getLocalPart());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            assertEquals(nodeList.getLength(), 1);

            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 0);
        }
    }
}