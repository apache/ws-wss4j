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
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.wss4j.binding.wssc.AbstractSecurityContextTokenType;
import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.derivedKey.ConversationConstants;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.SOAPUtil;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.dom.message.WSSecDKEncrypt;
import org.apache.wss4j.dom.message.WSSecDKSign;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecSecurityContextToken;
import org.apache.wss4j.dom.message.WSSecSignature;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.securityEvent.EncryptedPartSecurityEvent;
import org.apache.wss4j.stax.securityEvent.OperationSecurityEvent;
import org.apache.wss4j.stax.securityEvent.SignedPartSecurityEvent;
import org.apache.wss4j.stax.securityEvent.WSSecurityEventConstants;
import org.apache.wss4j.stax.setup.InboundWSSec;
import org.apache.wss4j.stax.setup.OutboundWSSec;
import org.apache.wss4j.stax.setup.WSSec;
import org.apache.wss4j.stax.test.utils.SecretKeyCallbackHandler;
import org.apache.wss4j.stax.test.utils.StAX2DOM;
import org.apache.wss4j.stax.test.utils.XmlReaderToWriter;
import org.apache.wss4j.stax.validate.SecurityContextTokenValidator;
import org.apache.wss4j.stax.validate.SecurityContextTokenValidatorImpl;
import org.apache.wss4j.stax.validate.TokenContext;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SignatureValueSecurityEvent;
import org.apache.xml.security.stax.securityToken.InboundSecurityToken;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SecurityContextTokenTest extends AbstractTestBase {

    @BeforeAll
    public static void setUp() throws Exception {
        WSSConfig.init();
    }

    @ParameterizedTest
    @ValueSource(ints = {ConversationConstants.VERSION_05_02, ConversationConstants.VERSION_05_12})
    public void testSCTDKTEncryptOutbound(int version) throws Exception {
        byte[] secret = WSSConstants.generateBytes(128 / 8);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.ENCRYPTION_WITH_DERIVED_KEY);
            securityProperties.setActions(actions);
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl(secret);
            securityProperties.setCallbackHandler(callbackHandler);
            securityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setEncryptionUser("receiver");
            securityProperties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#aes128-cbc");
            securityProperties.setDerivedKeyTokenReference(WSSConstants.DerivedKeyTokenReference.SecurityContextToken);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_SOAP11_BODY.getLocalPart());
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_WSC0512_SCT.getNamespaceURI(), WSSConstants.TAG_WSC0512_SCT.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_WSC0512_DKT.getNamespaceURI(), WSSConstants.TAG_WSC0512_DKT.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_ReferenceList.getNamespaceURI(), WSSConstants.TAG_xenc_ReferenceList.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.getLength(), 0);
        }
        {
            String action = WSHandlerConstants.ENCRYPTION;
            Properties properties = new Properties();
            WSS4JCallbackHandlerImpl callbackHandler = new WSS4JCallbackHandlerImpl(secret);
            properties.put(WSHandlerConstants.PW_CALLBACK_REF, callbackHandler);
            doInboundSecurityWithWSS4J_1(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action, properties, false);
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {ConversationConstants.VERSION_05_02, ConversationConstants.VERSION_05_12})
    public void testSCTDKTEncryptInbound(int version) throws Exception {

        byte[] tempSecret = XMLSecurityConstants.generateBytes(16);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
            WSSecHeader secHeader = new WSSecHeader(doc);
            secHeader.insertSecurityHeader();

            WSSecSecurityContextToken sctBuilder = new WSSecSecurityContextToken(secHeader, null);
            sctBuilder.setWscVersion(version);
            Crypto crypto = CryptoFactory.getInstance("transmitter-crypto.properties");
            sctBuilder.prepare(crypto);

            // Store the secret
            SecretKeyCallbackHandler callbackHandler = new SecretKeyCallbackHandler();
            callbackHandler.addSecretKey(sctBuilder.getIdentifier(), tempSecret);

            String tokenId = sctBuilder.getSctId();

            // Derived key encryption
            WSSecDKEncrypt encrBuilder = new WSSecDKEncrypt(secHeader);
            encrBuilder.setWscVersion(version);
            encrBuilder.setSymmetricEncAlgorithm(WSConstants.AES_128);
            encrBuilder.setTokenIdentifier(tokenId);
            encrBuilder.build(tempSecret);

            sctBuilder.prependSCTElementToHeader();

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(doc), new StreamResult(baos));
        }

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl(tempSecret);
            securityProperties.setCallbackHandler(callbackHandler);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);

            WSSecurityEventConstants.Event[] expectedSecurityEvents = new WSSecurityEventConstants.Event[]{
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.SECURITY_CONTEXT_TOKEN,
                    WSSecurityEventConstants.ENCRYPTED_PART,
                    WSSecurityEventConstants.OPERATION,
            };
            final TestSecurityEventListener securityEventListener = new TestSecurityEventListener(expectedSecurityEvents);

            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), null, securityEventListener);

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
            for (SecurityEvent securityEvent : securityEvents) {
                if (securityEvent.getCorrelationID().equals(encryptedPartCorrelationID)) {
                    encryptedPartSecurityEvents.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(operationCorrelationID)) {
                    operationSecurityEvents.add(securityEvent);
                }
            }

            assertEquals(5, encryptedPartSecurityEvents.size());
            assertEquals(securityEventListener.getReceivedSecurityEvents().size(),
                    operationSecurityEvents.size() +
                            encryptedPartSecurityEvents.size()
            );
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {ConversationConstants.VERSION_05_02, ConversationConstants.VERSION_05_12})
    public void testSCTDKTEncryptInboundAction(int version) throws Exception {

        byte[] tempSecret = XMLSecurityConstants.generateBytes(16);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.ENCRYPTION_DERIVED;

            Properties properties = new Properties();
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl(tempSecret);
            properties.put(WSHandlerConstants.PW_CALLBACK_REF, callbackHandler);
            properties.put(WSHandlerConstants.DERIVED_TOKEN_REFERENCE, "SecurityContextToken");
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
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl(tempSecret);
            securityProperties.setCallbackHandler(callbackHandler);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);

            WSSecurityEventConstants.Event[] expectedSecurityEvents = new WSSecurityEventConstants.Event[]{
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.SECURITY_CONTEXT_TOKEN,
                    WSSecurityEventConstants.ENCRYPTED_PART,
                    WSSecurityEventConstants.OPERATION,
            };
            final TestSecurityEventListener securityEventListener = new TestSecurityEventListener(expectedSecurityEvents);

            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), null, securityEventListener);

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
            for (SecurityEvent securityEvent : securityEvents) {
                if (securityEvent.getCorrelationID().equals(encryptedPartCorrelationID)) {
                    encryptedPartSecurityEvents.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(operationCorrelationID)) {
                    operationSecurityEvents.add(securityEvent);
                }
            }

            assertEquals(5, encryptedPartSecurityEvents.size());
            assertEquals(securityEventListener.getReceivedSecurityEvents().size(),
                    operationSecurityEvents.size() +
                            encryptedPartSecurityEvents.size()
            );
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {ConversationConstants.VERSION_05_02, ConversationConstants.VERSION_05_12})
    public void testSCTKDKTSignOutbound(int version) throws Exception {
        byte[] secret = WSSConstants.generateBytes(128 / 8);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.SIGNATURE_WITH_DERIVED_KEY);
            securityProperties.setActions(actions);
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl(secret);
            securityProperties.setCallbackHandler(callbackHandler);
            securityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
            securityProperties.setSignatureUser("transmitter");
            securityProperties.setDerivedKeyTokenReference(WSSConstants.DerivedKeyTokenReference.SecurityContextToken);

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_WSC0512_SCT.getNamespaceURI(), WSSConstants.TAG_WSC0512_SCT.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_WSC0512_DKT.getNamespaceURI(), WSSConstants.TAG_WSC0512_DKT.getLocalPart());
            assertEquals(nodeList.getLength(), 1);
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_ReferenceList.getNamespaceURI(), WSSConstants.TAG_xenc_ReferenceList.getLocalPart());
            assertEquals(nodeList.getLength(), 0);
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            assertEquals(nodeList.getLength(), 0);
        }
        {
            String action = WSHandlerConstants.SIGNATURE;
            Properties properties = new Properties();
            WSS4JCallbackHandlerImpl callbackHandler = new WSS4JCallbackHandlerImpl(secret);
            properties.put(WSHandlerConstants.PW_CALLBACK_REF, callbackHandler);
            doInboundSecurityWithWSS4J_1(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action, properties, false);
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {ConversationConstants.VERSION_05_02, ConversationConstants.VERSION_05_12})
    public void testSCTKDKTSignInbound(int version) throws Exception {

        byte[] tempSecret = XMLSecurityConstants.generateBytes(16);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
            WSSecHeader secHeader = new WSSecHeader(doc);
            secHeader.insertSecurityHeader();

            WSSecSecurityContextToken sctBuilder = new WSSecSecurityContextToken(secHeader, null);
            sctBuilder.setWscVersion(version);
            Crypto crypto = CryptoFactory.getInstance("transmitter-crypto.properties");
            sctBuilder.prepare(crypto);

            // Store the secret
            SecretKeyCallbackHandler callbackHandler = new SecretKeyCallbackHandler();
            callbackHandler.addSecretKey(sctBuilder.getIdentifier(), tempSecret);

            String tokenId = sctBuilder.getSctId();

            // Derived key signature
            WSSecDKSign sigBuilder = new WSSecDKSign(secHeader);
            sigBuilder.setWscVersion(version);
            sigBuilder.setTokenIdentifier(tokenId);
            sigBuilder.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
            sigBuilder.build(tempSecret);

            sctBuilder.prependSCTElementToHeader();

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(doc), new StreamResult(baos));
        }

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl(tempSecret);
            securityProperties.setCallbackHandler(callbackHandler);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);

            WSSecurityEventConstants.Event[] expectedSecurityEvents = new WSSecurityEventConstants.Event[]{
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.SECURITY_CONTEXT_TOKEN,
                    WSSecurityEventConstants.SignatureValue,
                    WSSecurityEventConstants.SIGNED_PART,
                    WSSecurityEventConstants.OPERATION,
            };
            final TestSecurityEventListener securityEventListener = new TestSecurityEventListener(expectedSecurityEvents);

            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), null, securityEventListener);

            StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            securityEventListener.compare();

            SignedPartSecurityEvent signedPartSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.SIGNED_PART);
            SignatureValueSecurityEvent signatureValueSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.SignatureValue);
            OperationSecurityEvent operationSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.OPERATION);
            String signedElementCorrelationID = signedPartSecurityEvent.getCorrelationID();
            String signatureValueCorrelationID = signatureValueSecurityEvent.getCorrelationID();
            String operationCorrelationID = operationSecurityEvent.getCorrelationID();

            List<SecurityEvent> operationSecurityEvents = new ArrayList<>();
            List<SecurityEvent> signedElementSecurityEvents = new ArrayList<>();
            List<SecurityEvent> signatureValueSecurityEvents = new ArrayList<>();

            List<SecurityEvent> securityEvents = securityEventListener.getReceivedSecurityEvents();
            for (SecurityEvent securityEvent : securityEvents) {
                if (securityEvent.getCorrelationID().equals(signedElementCorrelationID)) {
                    signedElementSecurityEvents.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(signatureValueCorrelationID)) {
                    signatureValueSecurityEvents.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(operationCorrelationID)) {
                    operationSecurityEvents.add(securityEvent);
                }
            }

            assertEquals(3, signedElementSecurityEvents.size());
            assertEquals(6, signatureValueSecurityEvents.size());
            assertEquals(securityEventListener.getReceivedSecurityEvents().size(),
                    operationSecurityEvents.size() +
                            signedElementSecurityEvents.size() + signatureValueSecurityEvents.size()
            );
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {ConversationConstants.VERSION_05_02, ConversationConstants.VERSION_05_12})
    public void testSCTKDKTSignInboundAction(int version) throws Exception {

        byte[] tempSecret = XMLSecurityConstants.generateBytes(16);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SIGNATURE_DERIVED;

            Properties properties = new Properties();
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl(tempSecret);
            properties.put(WSHandlerConstants.PW_CALLBACK_REF, callbackHandler);
            properties.put(WSHandlerConstants.DERIVED_TOKEN_REFERENCE, "SecurityContextToken");
            if (version == ConversationConstants.VERSION_05_02) {
                properties.put(WSHandlerConstants.USE_2005_12_NAMESPACE, "false");
            }
            properties.put(WSHandlerConstants.USER, "transmitter");
            properties.put(WSHandlerConstants.ENC_SYM_ALGO,
                           "http://www.w3.org/2001/04/xmlenc#aes128-cbc");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            //some test that we can really sure we get what we want from WSS4J
            NodeList nodeList = securedDocument.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            assertEquals(nodeList.getLength(), 1);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl(tempSecret);
            securityProperties.setCallbackHandler(callbackHandler);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);

            WSSecurityEventConstants.Event[] expectedSecurityEvents = new WSSecurityEventConstants.Event[]{
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.SECURITY_CONTEXT_TOKEN,
                    WSSecurityEventConstants.SignatureValue,
                    WSSecurityEventConstants.SIGNED_PART,
                    WSSecurityEventConstants.OPERATION,
            };
            final TestSecurityEventListener securityEventListener = new TestSecurityEventListener(expectedSecurityEvents);

            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), null, securityEventListener);

            StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            securityEventListener.compare();

            SignedPartSecurityEvent signedPartSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.SIGNED_PART);
            SignatureValueSecurityEvent signatureValueSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.SignatureValue);
            OperationSecurityEvent operationSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.OPERATION);
            String signedElementCorrelationID = signedPartSecurityEvent.getCorrelationID();
            String signatureValueCorrelationID = signatureValueSecurityEvent.getCorrelationID();
            String operationCorrelationID = operationSecurityEvent.getCorrelationID();

            List<SecurityEvent> operationSecurityEvents = new ArrayList<>();
            List<SecurityEvent> signedElementSecurityEvents = new ArrayList<>();
            List<SecurityEvent> signatureValueSecurityEvents = new ArrayList<>();

            List<SecurityEvent> securityEvents = securityEventListener.getReceivedSecurityEvents();
            for (SecurityEvent securityEvent : securityEvents) {
                if (securityEvent.getCorrelationID().equals(signedElementCorrelationID)) {
                    signedElementSecurityEvents.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(signatureValueCorrelationID)) {
                    signatureValueSecurityEvents.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(operationCorrelationID)) {
                    operationSecurityEvents.add(securityEvent);
                }
            }

            assertEquals(3, signedElementSecurityEvents.size());
            assertEquals(6, signatureValueSecurityEvents.size());
            assertEquals(securityEventListener.getReceivedSecurityEvents().size(),
                    operationSecurityEvents.size() +
                            signedElementSecurityEvents.size() + signatureValueSecurityEvents.size()
            );
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {ConversationConstants.VERSION_05_02, ConversationConstants.VERSION_05_12})
    public void testSCTKDKTSignAbsoluteInbound(int version) throws Exception {

        byte[] tempSecret = XMLSecurityConstants.generateBytes(16);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
            WSSecHeader secHeader = new WSSecHeader(doc);
            secHeader.insertSecurityHeader();

            WSSecSecurityContextToken sctBuilder = new WSSecSecurityContextToken(secHeader, null);
            sctBuilder.setWscVersion(version);
            Crypto crypto = CryptoFactory.getInstance("transmitter-crypto.properties");
            sctBuilder.prepare(crypto);

            // Store the secret
            SecretKeyCallbackHandler callbackHandler = new SecretKeyCallbackHandler();
            callbackHandler.addSecretKey(sctBuilder.getIdentifier(), tempSecret);

            // Derived key signature
            WSSecDKSign sigBuilder = new WSSecDKSign(secHeader);
            sigBuilder.setWscVersion(version);
            sigBuilder.setTokenIdDirectId(true);
            sigBuilder.setTokenIdentifier(sctBuilder.getIdentifier());
            sigBuilder.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
            sigBuilder.build(tempSecret);

            sctBuilder.prependSCTElementToHeader();

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(doc), new StreamResult(baos));
        }

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl(tempSecret);
            securityProperties.setCallbackHandler(callbackHandler);
            securityProperties.addIgnoreBSPRule(BSPRule.R5204);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {ConversationConstants.VERSION_05_02, ConversationConstants.VERSION_05_12})
    public void testSCTKDKTSignEncrypt(int version) throws Exception {

        byte[] tempSecret = XMLSecurityConstants.generateBytes(16);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
            WSSecHeader secHeader = new WSSecHeader(doc);
            secHeader.insertSecurityHeader();

            WSSecSecurityContextToken sctBuilder = new WSSecSecurityContextToken(secHeader, null);
            sctBuilder.setWscVersion(version);
            Crypto crypto = CryptoFactory.getInstance("transmitter-crypto.properties");
            sctBuilder.prepare(crypto);

            // Store the secret
            SecretKeyCallbackHandler callbackHandler = new SecretKeyCallbackHandler();
            callbackHandler.addSecretKey(sctBuilder.getIdentifier(), tempSecret);

            String tokenId = sctBuilder.getSctId();

            // Derived key signature
            WSSecDKSign sigBuilder = new WSSecDKSign(secHeader);
            sigBuilder.setWscVersion(version);
            if (version == ConversationConstants.VERSION_05_12) {
                sigBuilder.setCustomValueType(WSConstants.WSC_SCT_05_12);
            } else {
                sigBuilder.setCustomValueType(WSConstants.WSC_SCT);
            }
            sigBuilder.setTokenIdentifier(tokenId);
            sigBuilder.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
            sigBuilder.build(tempSecret);

            // Derived key encryption
            WSSecDKEncrypt encrBuilder = new WSSecDKEncrypt(secHeader);
            encrBuilder.setWscVersion(version);
            if (version == ConversationConstants.VERSION_05_12) {
                encrBuilder.setCustomValueType(WSConstants.WSC_SCT_05_12);
            } else {
                encrBuilder.setCustomValueType(WSConstants.WSC_SCT);
            }
            encrBuilder.setSymmetricEncAlgorithm(WSConstants.AES_128);
            encrBuilder.setTokenIdentifier(tokenId);
            encrBuilder.build(tempSecret);

            sctBuilder.prependSCTElementToHeader();

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(doc), new StreamResult(baos));
        }

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl(tempSecret);
            securityProperties.setCallbackHandler(callbackHandler);
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
                    WSSecurityEventConstants.SECURITY_CONTEXT_TOKEN,
                    WSSecurityEventConstants.SignatureValue,
                    WSSecurityEventConstants.SIGNED_PART,
                    WSSecurityEventConstants.ENCRYPTED_PART,
                    WSSecurityEventConstants.OPERATION,
            };
            final TestSecurityEventListener securityEventListener = new TestSecurityEventListener(expectedSecurityEvents);

            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), null, securityEventListener);

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 0);

            securityEventListener.compare();

            SignedPartSecurityEvent signedPartSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.SIGNED_PART);
            SignatureValueSecurityEvent signatureValueSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.SignatureValue);
            EncryptedPartSecurityEvent encryptedPartSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.ENCRYPTED_PART);
            OperationSecurityEvent operationSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.OPERATION);
            String signedElementCorrelationID = signedPartSecurityEvent.getCorrelationID();
            String signatureValueCorrelationID = signatureValueSecurityEvent.getCorrelationID();
            String encryptedPartCorrelationID = encryptedPartSecurityEvent.getCorrelationID();
            String operationCorrelationID = operationSecurityEvent.getCorrelationID();

            List<SecurityEvent> operationSecurityEvents = new ArrayList<>();
            List<SecurityEvent> signedElementSecurityEvents = new ArrayList<>();
            List<SecurityEvent> signatureValueSecurityEvents = new ArrayList<>();
            List<SecurityEvent> encryptedPartSecurityEvents = new ArrayList<>();

            List<SecurityEvent> securityEvents = securityEventListener.getReceivedSecurityEvents();
            for (SecurityEvent securityEvent : securityEvents) {
                if (securityEvent.getCorrelationID().equals(signedElementCorrelationID)) {
                    signedElementSecurityEvents.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(signatureValueCorrelationID)) {
                    signatureValueSecurityEvents.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(encryptedPartCorrelationID)) {
                    encryptedPartSecurityEvents.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(operationCorrelationID)) {
                    operationSecurityEvents.add(securityEvent);
                }
            }

            assertEquals(3, signedElementSecurityEvents.size());
            assertEquals(5, signatureValueSecurityEvents.size());
            assertEquals(5, encryptedPartSecurityEvents.size());
            assertEquals(securityEventListener.getReceivedSecurityEvents().size(),
                    operationSecurityEvents.size() +
                            signedElementSecurityEvents.size() + signatureValueSecurityEvents.size() + encryptedPartSecurityEvents.size()
            );
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {ConversationConstants.VERSION_05_02, ConversationConstants.VERSION_05_12})
    public void testSCTKDKTSignEncryptAction(int version) throws Exception {

        byte[] tempSecret = XMLSecurityConstants.generateBytes(16);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action =
                WSHandlerConstants.SIGNATURE_DERIVED + " " + WSHandlerConstants.ENCRYPTION_DERIVED;

            Properties properties = new Properties();
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl(tempSecret);
            properties.put(WSHandlerConstants.PW_CALLBACK_REF, callbackHandler);
            properties.put(WSHandlerConstants.DERIVED_TOKEN_REFERENCE, "SecurityContextToken");
            if (version == ConversationConstants.VERSION_05_02) {
                properties.put(WSHandlerConstants.USE_2005_12_NAMESPACE, "false");
            }
            properties.put(WSHandlerConstants.USER, "transmitter");
            properties.put(WSHandlerConstants.ENC_SYM_ALGO,
                           "http://www.w3.org/2001/04/xmlenc#aes128-cbc");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl(tempSecret);
            securityProperties.setCallbackHandler(callbackHandler);
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
                    WSSecurityEventConstants.SECURITY_CONTEXT_TOKEN,
                    WSSecurityEventConstants.SignatureValue,
                    WSSecurityEventConstants.SIGNED_PART,
                    WSSecurityEventConstants.ENCRYPTED_PART,
                    WSSecurityEventConstants.OPERATION,
            };
            final TestSecurityEventListener securityEventListener = new TestSecurityEventListener(expectedSecurityEvents);

            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray()));
            XMLStreamReader secureXmlStreamReader = wsSecIn.processInMessage(xmlStreamReader, null, securityEventListener);

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), secureXmlStreamReader);

            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 0);

            securityEventListener.compare();

            SignedPartSecurityEvent signedPartSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.SIGNED_PART);
            SignatureValueSecurityEvent signatureValueSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.SignatureValue);
            EncryptedPartSecurityEvent encryptedPartSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.ENCRYPTED_PART);
            OperationSecurityEvent operationSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.OPERATION);
            String signedElementCorrelationID = signedPartSecurityEvent.getCorrelationID();
            String signatureValueCorrelationID = signatureValueSecurityEvent.getCorrelationID();
            String encryptedPartCorrelationID = encryptedPartSecurityEvent.getCorrelationID();
            String operationCorrelationID = operationSecurityEvent.getCorrelationID();

            List<SecurityEvent> operationSecurityEvents = new ArrayList<>();
            List<SecurityEvent> signedElementSecurityEvents = new ArrayList<>();
            List<SecurityEvent> signatureValueSecurityEvents = new ArrayList<>();
            List<SecurityEvent> encryptedPartSecurityEvents = new ArrayList<>();

            List<SecurityEvent> securityEvents = securityEventListener.getReceivedSecurityEvents();
            for (SecurityEvent securityEvent : securityEvents) {
                if (securityEvent.getCorrelationID().equals(signedElementCorrelationID)) {
                    signedElementSecurityEvents.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(signatureValueCorrelationID)) {
                    signatureValueSecurityEvents.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(encryptedPartCorrelationID)) {
                    encryptedPartSecurityEvents.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(operationCorrelationID)) {
                    operationSecurityEvents.add(securityEvent);
                }
            }

            assertEquals(3, signedElementSecurityEvents.size());
            assertEquals(5, signatureValueSecurityEvents.size());
            assertEquals(5, encryptedPartSecurityEvents.size());
            assertEquals(securityEventListener.getReceivedSecurityEvents().size(),
                    operationSecurityEvents.size() +
                            signedElementSecurityEvents.size() + signatureValueSecurityEvents.size() + encryptedPartSecurityEvents.size()
            );
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {ConversationConstants.VERSION_05_02, ConversationConstants.VERSION_05_12})
    public void testSCTKDKTEncryptSign(int version) throws Exception {

        byte[] tempSecret = XMLSecurityConstants.generateBytes(16);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
            WSSecHeader secHeader = new WSSecHeader(doc);
            secHeader.insertSecurityHeader();

            WSSecSecurityContextToken sctBuilder = new WSSecSecurityContextToken(secHeader, null);
            sctBuilder.setWscVersion(version);
            Crypto crypto = CryptoFactory.getInstance("transmitter-crypto.properties");
            sctBuilder.prepare(crypto);

            // Store the secret
            SecretKeyCallbackHandler callbackHandler = new SecretKeyCallbackHandler();
            callbackHandler.addSecretKey(sctBuilder.getIdentifier(), tempSecret);

            String tokenId = sctBuilder.getSctId();

            // Derived key encryption
            WSSecDKEncrypt encrBuilder = new WSSecDKEncrypt(secHeader);
            encrBuilder.setWscVersion(version);
            if (version == ConversationConstants.VERSION_05_12) {
                encrBuilder.setCustomValueType(WSConstants.WSC_SCT_05_12);
            } else {
                encrBuilder.setCustomValueType(WSConstants.WSC_SCT);
            }
            encrBuilder.setSymmetricEncAlgorithm(WSConstants.AES_128);
            encrBuilder.setTokenIdentifier(tokenId);
            encrBuilder.build(tempSecret);

            // Derived key signature
            WSSecDKSign sigBuilder = new WSSecDKSign(secHeader);
            sigBuilder.setWscVersion(version);
            if (version == ConversationConstants.VERSION_05_12) {
                sigBuilder.setCustomValueType(WSConstants.WSC_SCT_05_12);
            } else {
                sigBuilder.setCustomValueType(WSConstants.WSC_SCT);
            }
            sigBuilder.setTokenIdentifier(tokenId);
            sigBuilder.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
            sigBuilder.build(tempSecret);

            sctBuilder.prependSCTElementToHeader();

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(doc), new StreamResult(baos));
        }

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl(tempSecret);
            securityProperties.setCallbackHandler(callbackHandler);
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
                    WSSecurityEventConstants.SECURITY_CONTEXT_TOKEN,
                    WSSecurityEventConstants.SignatureValue,
                    WSSecurityEventConstants.SIGNED_PART,
                    WSSecurityEventConstants.ENCRYPTED_PART,
                    WSSecurityEventConstants.OPERATION,
            };
            final TestSecurityEventListener securityEventListener = new TestSecurityEventListener(expectedSecurityEvents);

            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), null, securityEventListener);

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 0);

            securityEventListener.compare();

            SignedPartSecurityEvent signedPartSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.SIGNED_PART);
            SignatureValueSecurityEvent signatureValueSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.SignatureValue);
            EncryptedPartSecurityEvent encryptedPartSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.ENCRYPTED_PART);
            OperationSecurityEvent operationSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.OPERATION);
            String signedElementCorrelationID = signedPartSecurityEvent.getCorrelationID();
            String signatureValueCorrelationID = signatureValueSecurityEvent.getCorrelationID();
            String encryptedPartCorrelationID = encryptedPartSecurityEvent.getCorrelationID();
            String operationCorrelationID = operationSecurityEvent.getCorrelationID();

            List<SecurityEvent> operationSecurityEvents = new ArrayList<>();
            List<SecurityEvent> signedElementSecurityEvents = new ArrayList<>();
            List<SecurityEvent> signatureValueSecurityEvents = new ArrayList<>();
            List<SecurityEvent> encryptedPartSecurityEvents = new ArrayList<>();

            List<SecurityEvent> securityEvents = securityEventListener.getReceivedSecurityEvents();
            for (SecurityEvent securityEvent : securityEvents) {
                if (securityEvent.getCorrelationID().equals(signedElementCorrelationID)) {
                    signedElementSecurityEvents.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(signatureValueCorrelationID)) {
                    signatureValueSecurityEvents.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(encryptedPartCorrelationID)) {
                    encryptedPartSecurityEvents.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(operationCorrelationID)) {
                    operationSecurityEvents.add(securityEvent);
                }
            }

            assertEquals(3, signedElementSecurityEvents.size());
            assertEquals(5, signatureValueSecurityEvents.size());
            assertEquals(5, encryptedPartSecurityEvents.size());
            assertEquals(securityEventListener.getReceivedSecurityEvents().size(),
                    operationSecurityEvents.size() +
                            signedElementSecurityEvents.size() + signatureValueSecurityEvents.size() + encryptedPartSecurityEvents.size()
            );
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {ConversationConstants.VERSION_05_02, ConversationConstants.VERSION_05_12})
    public void testSCTKDKTEncryptSignAction(int version) throws Exception {

        byte[] tempSecret = XMLSecurityConstants.generateBytes(16);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action =
                WSHandlerConstants.ENCRYPTION_DERIVED + " " + WSHandlerConstants.SIGNATURE_DERIVED;

            Properties properties = new Properties();
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl(tempSecret);
            properties.put(WSHandlerConstants.PW_CALLBACK_REF, callbackHandler);
            properties.put(WSHandlerConstants.DERIVED_TOKEN_REFERENCE, "SecurityContextToken");
            if (version == ConversationConstants.VERSION_05_02) {
                properties.put(WSHandlerConstants.USE_2005_12_NAMESPACE, "false");
            }
            properties.put(WSHandlerConstants.USER, "transmitter");
            properties.put(WSHandlerConstants.ENC_SYM_ALGO,
                           "http://www.w3.org/2001/04/xmlenc#aes128-cbc");
            Document securedDocument = doOutboundSecurityWithWSS4J(sourceDocument, action, properties);

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(securedDocument), new StreamResult(baos));
        }

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl(tempSecret);
            securityProperties.setCallbackHandler(callbackHandler);
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
                    WSSecurityEventConstants.SECURITY_CONTEXT_TOKEN,
                    WSSecurityEventConstants.SignatureValue,
                    WSSecurityEventConstants.SIGNED_PART,
                    WSSecurityEventConstants.ENCRYPTED_PART,
                    WSSecurityEventConstants.OPERATION,
            };
            final TestSecurityEventListener securityEventListener = new TestSecurityEventListener(expectedSecurityEvents);

            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())), null, securityEventListener);

            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(nodeList.getLength(), 0);

            securityEventListener.compare();

            SignedPartSecurityEvent signedPartSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.SIGNED_PART);
            SignatureValueSecurityEvent signatureValueSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.SignatureValue);
            EncryptedPartSecurityEvent encryptedPartSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.ENCRYPTED_PART);
            OperationSecurityEvent operationSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.OPERATION);
            String signedElementCorrelationID = signedPartSecurityEvent.getCorrelationID();
            String signatureValueCorrelationID = signatureValueSecurityEvent.getCorrelationID();
            String encryptedPartCorrelationID = encryptedPartSecurityEvent.getCorrelationID();
            String operationCorrelationID = operationSecurityEvent.getCorrelationID();

            List<SecurityEvent> operationSecurityEvents = new ArrayList<>();
            List<SecurityEvent> signedElementSecurityEvents = new ArrayList<>();
            List<SecurityEvent> signatureValueSecurityEvents = new ArrayList<>();
            List<SecurityEvent> encryptedPartSecurityEvents = new ArrayList<>();

            List<SecurityEvent> securityEvents = securityEventListener.getReceivedSecurityEvents();
            for (SecurityEvent securityEvent : securityEvents) {
                if (securityEvent.getCorrelationID().equals(signedElementCorrelationID)) {
                    signedElementSecurityEvents.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(signatureValueCorrelationID)) {
                    signatureValueSecurityEvents.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(encryptedPartCorrelationID)) {
                    encryptedPartSecurityEvents.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(operationCorrelationID)) {
                    operationSecurityEvents.add(securityEvent);
                }
            }

            assertEquals(3, signedElementSecurityEvents.size());
            assertEquals(5, signatureValueSecurityEvents.size());
            assertEquals(5, encryptedPartSecurityEvents.size());
            assertEquals(securityEventListener.getReceivedSecurityEvents().size(),
                    operationSecurityEvents.size() +
                            signedElementSecurityEvents.size() + signatureValueSecurityEvents.size() + encryptedPartSecurityEvents.size()
            );
        }
    }


    @ParameterizedTest
    @ValueSource(ints = {ConversationConstants.VERSION_05_02, ConversationConstants.VERSION_05_12})
    public void testSCTSign(int version) throws Exception {

        byte[] tempSecret = XMLSecurityConstants.generateBytes(16);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
            WSSecHeader secHeader = new WSSecHeader(doc);
            secHeader.insertSecurityHeader();

            WSSecSecurityContextToken sctBuilder = new WSSecSecurityContextToken(secHeader, null);
            sctBuilder.setWscVersion(version);
            Crypto crypto = CryptoFactory.getInstance("transmitter-crypto.properties");
            sctBuilder.prepare(crypto);

            // Store the secret
            SecretKeyCallbackHandler callbackHandler = new SecretKeyCallbackHandler();
            callbackHandler.addSecretKey(sctBuilder.getIdentifier(), tempSecret);

            String tokenId = sctBuilder.getSctId();

            WSSecSignature builder = new WSSecSignature(secHeader);
            builder.setSecretKey(tempSecret);
            builder.setKeyIdentifierType(WSConstants.CUSTOM_SYMM_SIGNING);
            builder.setCustomTokenValueType(WSConstants.WSC_SCT);
            builder.setCustomTokenId(tokenId);
            builder.setSignatureAlgorithm(SignatureMethod.HMAC_SHA1);
            builder.build(crypto);

            sctBuilder.prependSCTElementToHeader();

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(doc), new StreamResult(baos));
        }

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl(tempSecret);
            securityProperties.setCallbackHandler(callbackHandler);
            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);

            WSSecurityEventConstants.Event[] expectedSecurityEvents = new WSSecurityEventConstants.Event[]{
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.AlgorithmSuite,
                    WSSecurityEventConstants.SECURITY_CONTEXT_TOKEN,
                    WSSecurityEventConstants.SignatureValue,
                    WSSecurityEventConstants.SIGNED_PART,
                    WSSecurityEventConstants.OPERATION,
            };
            final TestSecurityEventListener securityEventListener = new TestSecurityEventListener(expectedSecurityEvents);

            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray()));
            XMLStreamReader secureXmlStreamReader = wsSecIn.processInMessage(xmlStreamReader, null, securityEventListener);

            StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), secureXmlStreamReader);

            securityEventListener.compare();

            SignedPartSecurityEvent signedPartSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.SIGNED_PART);
            SignatureValueSecurityEvent signatureValueSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.SignatureValue);
            OperationSecurityEvent operationSecurityEvent = securityEventListener.getSecurityEvent(WSSecurityEventConstants.OPERATION);
            String signedElementCorrelationID = signedPartSecurityEvent.getCorrelationID();
            String signatureValueCorrelationID = signatureValueSecurityEvent.getCorrelationID();
            String operationCorrelationID = operationSecurityEvent.getCorrelationID();

            List<SecurityEvent> operationSecurityEvents = new ArrayList<>();
            List<SecurityEvent> signedElementSecurityEvents = new ArrayList<>();
            List<SecurityEvent> signatureValueSecurityEvents = new ArrayList<>();

            List<SecurityEvent> securityEvents = securityEventListener.getReceivedSecurityEvents();
            for (SecurityEvent securityEvent : securityEvents) {
                if (securityEvent.getCorrelationID().equals(signedElementCorrelationID)) {
                    signedElementSecurityEvents.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(signatureValueCorrelationID)) {
                    signatureValueSecurityEvents.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(operationCorrelationID)) {
                    operationSecurityEvents.add(securityEvent);
                }
            }

            assertEquals(3, signedElementSecurityEvents.size());
            assertEquals(4, signatureValueSecurityEvents.size());
            assertEquals(securityEventListener.getReceivedSecurityEvents().size(),
                    operationSecurityEvents.size() +
                            signedElementSecurityEvents.size() + signatureValueSecurityEvents.size()
            );
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {ConversationConstants.VERSION_05_02, ConversationConstants.VERSION_05_12})
    public void testSCTCustomValidator(int version) throws Exception {
        byte[] tempSecret = XMLSecurityConstants.generateBytes(16);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
            WSSecHeader secHeader = new WSSecHeader(doc);
            secHeader.insertSecurityHeader();

            WSSecSecurityContextToken sctBuilder = new WSSecSecurityContextToken(secHeader, null);
            sctBuilder.setWscVersion(version);
            Crypto crypto = CryptoFactory.getInstance("transmitter-crypto.properties");
            sctBuilder.prepare(crypto);

            // Store the secret
            SecretKeyCallbackHandler callbackHandler = new SecretKeyCallbackHandler();
            callbackHandler.addSecretKey(sctBuilder.getIdentifier(), tempSecret);

            String tokenId = sctBuilder.getSctId();

            WSSecSignature builder = new WSSecSignature(secHeader);
            builder.setSecretKey(tempSecret);
            builder.setKeyIdentifierType(WSConstants.CUSTOM_SYMM_SIGNING);
            builder.setCustomTokenValueType(WSConstants.WSC_SCT);
            builder.setCustomTokenId(tokenId);
            builder.setSignatureAlgorithm(SignatureMethod.HMAC_SHA1);
            builder.build(crypto);

            sctBuilder.prependSCTElementToHeader();

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(doc), new StreamResult(baos));
        }

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl(tempSecret);
            securityProperties.setCallbackHandler(callbackHandler);

            final boolean[] validatorCalled = {false};
            SecurityContextTokenValidator validator = new SecurityContextTokenValidatorImpl() {
                @Override
                public InboundSecurityToken validate(AbstractSecurityContextTokenType securityContextTokenType, String identifier, TokenContext tokenContext) throws WSSecurityException {
                    validatorCalled[0] = true;
                    return super.validate(securityContextTokenType, identifier, tokenContext);
                }
            };

            if (version == ConversationConstants.VERSION_05_02) {
                securityProperties.addValidator(WSSConstants.TAG_WSC0502_SCT, validator);
            } else {
                securityProperties.addValidator(WSSConstants.TAG_WSC0512_SCT, validator);
            }

            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);

            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray()));
            XMLStreamReader secureXmlStreamReader = wsSecIn.processInMessage(xmlStreamReader);

            StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), secureXmlStreamReader);

            assertTrue(validatorCalled[0], "Validator should be called when configured");
        }
    }
}
