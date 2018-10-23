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
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Properties;

import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.derivedKey.ConversationConstants;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.dom.message.WSSecDKEncrypt;
import org.apache.wss4j.dom.message.WSSecDKSign;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecSecurityContextToken;
import org.apache.wss4j.dom.message.WSSecSignature;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.securityEvent.EncryptedPartSecurityEvent;
import org.apache.wss4j.stax.securityEvent.OperationSecurityEvent;
import org.apache.wss4j.stax.securityEvent.SignedPartSecurityEvent;
import org.apache.wss4j.stax.securityEvent.WSSecurityEventConstants;
import org.apache.wss4j.stax.setup.InboundWSSec;
import org.apache.wss4j.stax.setup.OutboundWSSec;
import org.apache.wss4j.stax.setup.WSSec;
import org.apache.wss4j.stax.test.utils.SOAPUtil;
import org.apache.wss4j.stax.test.utils.SecretKeyCallbackHandler;
import org.apache.wss4j.stax.test.utils.StAX2DOM;
import org.apache.wss4j.stax.test.utils.XmlReaderToWriter;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SignatureValueSecurityEvent;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized.Parameters;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

@RunWith(value = org.junit.runners.Parameterized.class)
public class SecurityContextTokenTest extends AbstractTestBase {

    final int version;

    public SecurityContextTokenTest(int version) {
        this.version = version;
    }

    @Parameters(name = "{0}")
    public static Collection<Object[]> data() {

        return Arrays.asList(new Object[][] {{ConversationConstants.VERSION_05_02},
                                             {ConversationConstants.VERSION_05_12}
        });
    }

    @BeforeClass
    public static void setUp() throws Exception {
        WSSConfig.init();
    }

    @Test
    public void testSCTDKTEncryptOutbound() throws Exception {
        byte[] secret = WSSConstants.generateBytes(128 / 8);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.ENCRYPT_WITH_DERIVED_KEY);
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
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_SOAP11_BODY.getLocalPart());
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_WSC0512_SCT.getNamespaceURI(), WSSConstants.TAG_WSC0512_SCT.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_WSC0512_DKT.getNamespaceURI(), WSSConstants.TAG_WSC0512_DKT.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_ReferenceList.getNamespaceURI(), WSSConstants.TAG_xenc_ReferenceList.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }
        {
            String action = WSHandlerConstants.ENCRYPT;
            Properties properties = new Properties();
            WSS4JCallbackHandlerImpl callbackHandler = new WSS4JCallbackHandlerImpl(secret);
            properties.put(WSHandlerConstants.PW_CALLBACK_REF, callbackHandler);
            doInboundSecurityWithWSS4J_1(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action, properties, false);
        }
    }

    @Test
    public void testSCTDKTEncryptInbound() throws Exception {

        byte[] tempSecret = WSSecurityUtil.generateNonce(16);
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
            encrBuilder.setExternalKey(tempSecret, tokenId);
            encrBuilder.build();

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
            Assert.assertEquals(nodeList.getLength(), 0);

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

            Assert.assertEquals(5, encryptedPartSecurityEvents.size());
            Assert.assertEquals(securityEventListener.getReceivedSecurityEvents().size(),
                    operationSecurityEvents.size() +
                            encryptedPartSecurityEvents.size()
            );
        }
    }

    @Test
    public void testSCTDKTEncryptInboundAction() throws Exception {

        byte[] tempSecret = WSSecurityUtil.generateNonce(16);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.ENCRYPT_DERIVED;

            Properties properties = new Properties();
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl(tempSecret);
            properties.put(WSHandlerConstants.PW_CALLBACK_REF,  callbackHandler);
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
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_SOAP11_BODY.getLocalPart());

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
            Assert.assertEquals(nodeList.getLength(), 0);

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

            Assert.assertEquals(5, encryptedPartSecurityEvents.size());
            Assert.assertEquals(securityEventListener.getReceivedSecurityEvents().size(),
                    operationSecurityEvents.size() +
                            encryptedPartSecurityEvents.size()
            );
        }
    }

    @Test
    public void testSCTKDKTSignOutbound() throws Exception {
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
            Assert.assertEquals(nodeList.getLength(), 1);
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_WSC0512_SCT.getNamespaceURI(), WSSConstants.TAG_WSC0512_SCT.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_WSC0512_DKT.getNamespaceURI(), WSSConstants.TAG_WSC0512_DKT.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_ReferenceList.getNamespaceURI(), WSSConstants.TAG_xenc_ReferenceList.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);
        }
        {
            String action = WSHandlerConstants.SIGNATURE;
            Properties properties = new Properties();
            WSS4JCallbackHandlerImpl callbackHandler = new WSS4JCallbackHandlerImpl(secret);
            properties.put(WSHandlerConstants.PW_CALLBACK_REF, callbackHandler);
            doInboundSecurityWithWSS4J_1(documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray())), action, properties, false);
        }
    }

    @Test
    public void testSCTKDKTSignInbound() throws Exception {

        byte[] tempSecret = WSSecurityUtil.generateNonce(16);
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
            sigBuilder.setExternalKey(tempSecret, tokenId);
            sigBuilder.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
            sigBuilder.build();

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
            for (int i = 0; i < securityEvents.size(); i++) {
                SecurityEvent securityEvent = securityEvents.get(i);
                if (securityEvent.getCorrelationID().equals(signedElementCorrelationID)) {
                    signedElementSecurityEvents.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(signatureValueCorrelationID)) {
                    signatureValueSecurityEvents.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(operationCorrelationID)) {
                    operationSecurityEvents.add(securityEvent);
                }
            }

            Assert.assertEquals(3, signedElementSecurityEvents.size());
            Assert.assertEquals(6, signatureValueSecurityEvents.size());
            Assert.assertEquals(securityEventListener.getReceivedSecurityEvents().size(),
                    operationSecurityEvents.size() +
                            signedElementSecurityEvents.size() + signatureValueSecurityEvents.size()
            );
        }
    }

    @Test
    public void testSCTKDKTSignInboundAction() throws Exception {

        byte[] tempSecret = WSSecurityUtil.generateNonce(16);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action = WSHandlerConstants.SIGNATURE_DERIVED;

            Properties properties = new Properties();
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl(tempSecret);
            properties.put(WSHandlerConstants.PW_CALLBACK_REF,  callbackHandler);
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
            Assert.assertEquals(nodeList.getLength(), 1);

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
            for (int i = 0; i < securityEvents.size(); i++) {
                SecurityEvent securityEvent = securityEvents.get(i);
                if (securityEvent.getCorrelationID().equals(signedElementCorrelationID)) {
                    signedElementSecurityEvents.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(signatureValueCorrelationID)) {
                    signatureValueSecurityEvents.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(operationCorrelationID)) {
                    operationSecurityEvents.add(securityEvent);
                }
            }

            Assert.assertEquals(3, signedElementSecurityEvents.size());
            Assert.assertEquals(6, signatureValueSecurityEvents.size());
            Assert.assertEquals(securityEventListener.getReceivedSecurityEvents().size(),
                    operationSecurityEvents.size() +
                            signedElementSecurityEvents.size() + signatureValueSecurityEvents.size()
            );
        }
    }

    @Test
    public void testSCTKDKTSignAbsoluteInbound() throws Exception {

        byte[] tempSecret = WSSecurityUtil.generateNonce(16);
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
            sigBuilder.setExternalKey(tempSecret, sctBuilder.getIdentifier());
            sigBuilder.setTokenIdDirectId(true);
            sigBuilder.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
            sigBuilder.build();

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

    @Test()
    public void testSCTKDKTSignEncrypt() throws Exception {

        byte[] tempSecret = WSSecurityUtil.generateNonce(16);
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
            sigBuilder.setExternalKey(tempSecret, tokenId);
            sigBuilder.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
            sigBuilder.build();

            // Derived key encryption
            WSSecDKEncrypt encrBuilder = new WSSecDKEncrypt(secHeader);
            encrBuilder.setWscVersion(version);
            if (version == ConversationConstants.VERSION_05_12) {
                encrBuilder.setCustomValueType(WSConstants.WSC_SCT_05_12);
            } else {
                encrBuilder.setCustomValueType(WSConstants.WSC_SCT);
            }
            encrBuilder.setSymmetricEncAlgorithm(WSConstants.AES_128);
            encrBuilder.setExternalKey(tempSecret, tokenId);
            encrBuilder.build();

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
            Assert.assertEquals(nodeList.getLength(), 0);

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
            for (int i = 0; i < securityEvents.size(); i++) {
                SecurityEvent securityEvent = securityEvents.get(i);
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

            Assert.assertEquals(3, signedElementSecurityEvents.size());
            Assert.assertEquals(5, signatureValueSecurityEvents.size());
            Assert.assertEquals(5, encryptedPartSecurityEvents.size());
            Assert.assertEquals(securityEventListener.getReceivedSecurityEvents().size(),
                    operationSecurityEvents.size() +
                            signedElementSecurityEvents.size() + signatureValueSecurityEvents.size() + encryptedPartSecurityEvents.size()
            );
        }
    }

    @Test()
    public void testSCTKDKTSignEncryptAction() throws Exception {

        byte[] tempSecret = WSSecurityUtil.generateNonce(16);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action =
                WSHandlerConstants.SIGNATURE_DERIVED + " " + WSHandlerConstants.ENCRYPT_DERIVED;

            Properties properties = new Properties();
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl(tempSecret);
            properties.put(WSHandlerConstants.PW_CALLBACK_REF,  callbackHandler);
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
            Assert.assertEquals(nodeList.getLength(), 0);

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
            for (int i = 0; i < securityEvents.size(); i++) {
                SecurityEvent securityEvent = securityEvents.get(i);
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

            Assert.assertEquals(3, signedElementSecurityEvents.size());
            Assert.assertEquals(5, signatureValueSecurityEvents.size());
            Assert.assertEquals(5, encryptedPartSecurityEvents.size());
            Assert.assertEquals(securityEventListener.getReceivedSecurityEvents().size(),
                    operationSecurityEvents.size() +
                            signedElementSecurityEvents.size() + signatureValueSecurityEvents.size() + encryptedPartSecurityEvents.size()
            );
        }
    }

    @Test
    public void testSCTKDKTEncryptSign() throws Exception {

        byte[] tempSecret = WSSecurityUtil.generateNonce(16);
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
            encrBuilder.setExternalKey(tempSecret, tokenId);
            encrBuilder.build();

            // Derived key signature
            WSSecDKSign sigBuilder = new WSSecDKSign(secHeader);
            sigBuilder.setWscVersion(version);
            if (version == ConversationConstants.VERSION_05_12) {
                sigBuilder.setCustomValueType(WSConstants.WSC_SCT_05_12);
            } else {
                sigBuilder.setCustomValueType(WSConstants.WSC_SCT);
            }
            sigBuilder.setExternalKey(tempSecret, tokenId);
            sigBuilder.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
            sigBuilder.build();

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
            Assert.assertEquals(nodeList.getLength(), 0);

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
            for (int i = 0; i < securityEvents.size(); i++) {
                SecurityEvent securityEvent = securityEvents.get(i);
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

            Assert.assertEquals(3, signedElementSecurityEvents.size());
            Assert.assertEquals(5, signatureValueSecurityEvents.size());
            Assert.assertEquals(5, encryptedPartSecurityEvents.size());
            Assert.assertEquals(securityEventListener.getReceivedSecurityEvents().size(),
                    operationSecurityEvents.size() +
                            signedElementSecurityEvents.size() + signatureValueSecurityEvents.size() + encryptedPartSecurityEvents.size()
            );
        }
    }

    @Test
    public void testSCTKDKTEncryptSignAction() throws Exception {

        byte[] tempSecret = WSSecurityUtil.generateNonce(16);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            String action =
                WSHandlerConstants.ENCRYPT_DERIVED + " " + WSHandlerConstants.SIGNATURE_DERIVED;

            Properties properties = new Properties();
            CallbackHandlerImpl callbackHandler = new CallbackHandlerImpl(tempSecret);
            properties.put(WSHandlerConstants.PW_CALLBACK_REF,  callbackHandler);
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
            Assert.assertEquals(nodeList.getLength(), 0);

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
            for (int i = 0; i < securityEvents.size(); i++) {
                SecurityEvent securityEvent = securityEvents.get(i);
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

            Assert.assertEquals(3, signedElementSecurityEvents.size());
            Assert.assertEquals(5, signatureValueSecurityEvents.size());
            Assert.assertEquals(5, encryptedPartSecurityEvents.size());
            Assert.assertEquals(securityEventListener.getReceivedSecurityEvents().size(),
                    operationSecurityEvents.size() +
                            signedElementSecurityEvents.size() + signatureValueSecurityEvents.size() + encryptedPartSecurityEvents.size()
            );
        }
    }


    @Test
    public void testSCTSign() throws Exception {

        byte[] tempSecret = WSSecurityUtil.generateNonce(16);
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
            for (int i = 0; i < securityEvents.size(); i++) {
                SecurityEvent securityEvent = securityEvents.get(i);
                if (securityEvent.getCorrelationID().equals(signedElementCorrelationID)) {
                    signedElementSecurityEvents.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(signatureValueCorrelationID)) {
                    signatureValueSecurityEvents.add(securityEvent);
                } else if (securityEvent.getCorrelationID().equals(operationCorrelationID)) {
                    operationSecurityEvents.add(securityEvent);
                }
            }

            Assert.assertEquals(3, signedElementSecurityEvents.size());
            Assert.assertEquals(4, signatureValueSecurityEvents.size());
            Assert.assertEquals(securityEventListener.getReceivedSecurityEvents().size(),
                    operationSecurityEvents.size() +
                            signedElementSecurityEvents.size() + signatureValueSecurityEvents.size()
            );
        }
    }
}
