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

package org.apache.wss4j.dom.handler;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.callback.CallbackHandler;
import javax.xml.crypto.dsig.SignatureMethod;

import org.apache.wss4j.common.EncryptionActionToken;
import org.apache.wss4j.common.SignatureActionToken;
import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.KeyUtils;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.common.CombinedCallbackHandler;
import org.apache.wss4j.dom.common.CustomHandler;
import org.apache.wss4j.dom.common.KeystoreCallbackHandler;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.common.SecretKeyCallbackHandler;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Document;


/**
 * This is a set of tests for using SecurityActionTokens to configure various Actions.
 */
public class SecurityActionTokenTest extends org.junit.Assert {
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(SecurityActionTokenTest.class);
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private Crypto crypto;
    private byte[] keyData;

    @org.junit.AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }

    @Before
    public void setUp() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey key = keyGen.generateKey();
        keyData = key.getEncoded();
    }

    public SecurityActionTokenTest() throws WSSecurityException {
        WSSConfig.init();
        crypto = CryptoFactory.getInstance("wss40.properties");
    }

    @Test
    public void testAsymmetricSignature() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        java.util.Map<String, Object> messageContext = new java.util.TreeMap<String, Object>();
        messageContext.put(
            WSHandlerConstants.PW_CALLBACK_REF, new KeystoreCallbackHandler()
        );
        reqData.setMsgContext(messageContext);

        SignatureActionToken actionToken = new SignatureActionToken();
        actionToken.setUser("wss40");
        actionToken.setCryptoProperties("wss40.properties");

        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        List<HandlerAction> actions = new ArrayList<>();
        actions.add(new HandlerAction(WSConstants.SIGN, actionToken));
        handler.send(
            doc,
            reqData,
            actions,
            true
        );

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        verify(doc, null);
    }

    @Test
    public void testSymmetricSignature() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        java.util.Map<String, Object> messageContext = new java.util.TreeMap<String, Object>();
        messageContext.put(
            WSHandlerConstants.PW_CALLBACK_REF, new KeystoreCallbackHandler()
        );
        reqData.setMsgContext(messageContext);

        SignatureActionToken actionToken = new SignatureActionToken();
        actionToken.setKeyIdentifierId(WSConstants.ENCRYPTED_KEY_SHA1_IDENTIFIER);
        actionToken.setKey(keyData);
        actionToken.setSignatureAlgorithm(SignatureMethod.HMAC_SHA1);

        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        List<HandlerAction> actions = new ArrayList<>();
        actions.add(new HandlerAction(WSConstants.SIGN, actionToken));
        handler.send(
            doc,
            reqData,
            actions,
            true
        );

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        SecretKeyCallbackHandler secretKeyCallbackHandler = new SecretKeyCallbackHandler();
        byte[] encodedBytes = KeyUtils.generateDigest(keyData);
        String identifier = Base64.getMimeEncoder().encodeToString(encodedBytes);
        secretKeyCallbackHandler.addSecretKey(identifier, keyData);

        verify(doc, secretKeyCallbackHandler);
    }

    @Test
    public void testAsymmetricDoubleSignature() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        java.util.Map<String, Object> messageContext = new java.util.TreeMap<String, Object>();
        messageContext.put(
            WSHandlerConstants.PW_CALLBACK_REF, new KeystoreCallbackHandler()
        );
        reqData.setMsgContext(messageContext);

        SignatureActionToken actionToken = new SignatureActionToken();
        actionToken.setUser("wss40");
        actionToken.setCryptoProperties("wss40.properties");
        actionToken.setKeyIdentifierId(WSConstants.BST_DIRECT_REFERENCE);

        SignatureActionToken actionToken2 = new SignatureActionToken();
        actionToken2.setUser("16c73ab6-b892-458f-abf5-2f875f74882e");
        actionToken2.setCryptoProperties("crypto.properties");
        actionToken2.setIncludeToken(false);
        WSEncryptionPart encP =
            new WSEncryptionPart("Timestamp", WSConstants.WSU_NS, "");
        actionToken2.setParts(Collections.singletonList(encP));

        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        List<HandlerAction> actions = new ArrayList<>();
        actions.add(new HandlerAction(WSConstants.SIGN, actionToken));
        actions.add(new HandlerAction(WSConstants.SIGN, actionToken2));
        actions.add(new HandlerAction(WSConstants.TS, null));
        handler.send(
            doc,
            reqData,
            actions,
            true
        );

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        // Not verifying due to two separate Crypto instances...
    }

    @Test
    public void testMixedDoubleSignature() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        java.util.Map<String, Object> messageContext = new java.util.TreeMap<String, Object>();
        messageContext.put(
            WSHandlerConstants.PW_CALLBACK_REF, new KeystoreCallbackHandler()
        );
        reqData.setMsgContext(messageContext);

        SignatureActionToken actionToken = new SignatureActionToken();
        actionToken.setUser("wss40");
        actionToken.setCryptoProperties("wss40.properties");
        actionToken.setKeyIdentifierId(WSConstants.BST_DIRECT_REFERENCE);

        SignatureActionToken actionToken2 = new SignatureActionToken();
        actionToken2.setKeyIdentifierId(WSConstants.ENCRYPTED_KEY_SHA1_IDENTIFIER);
        actionToken2.setKey(keyData);
        actionToken2.setSignatureAlgorithm(SignatureMethod.HMAC_SHA1);
        WSEncryptionPart encP =
            new WSEncryptionPart("Timestamp", WSConstants.WSU_NS, "");
        actionToken2.setParts(Collections.singletonList(encP));

        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        List<HandlerAction> actions = new ArrayList<>();
        actions.add(new HandlerAction(WSConstants.SIGN, actionToken));
        actions.add(new HandlerAction(WSConstants.SIGN, actionToken2));
        actions.add(new HandlerAction(WSConstants.TS, null));
        handler.send(
            doc,
            reqData,
            actions,
            true
        );

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        SecretKeyCallbackHandler secretKeyCallbackHandler = new SecretKeyCallbackHandler();
        byte[] encodedBytes = KeyUtils.generateDigest(keyData);
        String identifier = Base64.getMimeEncoder().encodeToString(encodedBytes);
        secretKeyCallbackHandler.addSecretKey(identifier, keyData);

        verify(doc, secretKeyCallbackHandler);
    }

    @Test
    public void testAsymmetricEncryption() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        java.util.Map<String, Object> messageContext = new java.util.TreeMap<String, Object>();
        messageContext.put(
            WSHandlerConstants.PW_CALLBACK_REF, new KeystoreCallbackHandler()
        );
        reqData.setMsgContext(messageContext);

        EncryptionActionToken actionToken = new EncryptionActionToken();
        actionToken.setUser("wss40");
        actionToken.setCryptoProperties("wss40.properties");

        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        List<HandlerAction> actions = new ArrayList<>();
        actions.add(new HandlerAction(WSConstants.ENCR, actionToken));
        handler.send(
            doc,
            reqData,
            actions,
            true
        );

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        verify(doc, new KeystoreCallbackHandler());
    }

    @Test
    public void testAsymmetricEncryptionIncludeToken() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        java.util.Map<String, Object> messageContext = new java.util.TreeMap<String, Object>();
        messageContext.put(
            WSHandlerConstants.PW_CALLBACK_REF, new KeystoreCallbackHandler()
        );
        reqData.setMsgContext(messageContext);

        EncryptionActionToken actionToken = new EncryptionActionToken();
        actionToken.setUser("wss40");
        actionToken.setCryptoProperties("wss40.properties");
        actionToken.setIncludeToken(true);

        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        List<HandlerAction> actions = new ArrayList<>();
        actions.add(new HandlerAction(WSConstants.ENCR, actionToken));
        handler.send(
            doc,
            reqData,
            actions,
            true
        );

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        verify(doc, new KeystoreCallbackHandler());
    }

    @Test
    public void testSymmetricEncryption() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        java.util.Map<String, Object> messageContext = new java.util.TreeMap<String, Object>();
        messageContext.put(
            WSHandlerConstants.PW_CALLBACK_REF, new KeystoreCallbackHandler()
        );
        reqData.setMsgContext(messageContext);

        EncryptionActionToken actionToken = new EncryptionActionToken();
        actionToken.setKeyIdentifierId(WSConstants.ENCRYPTED_KEY_SHA1_IDENTIFIER);
        actionToken.setKey(keyData);
        actionToken.setSymmetricAlgorithm(WSConstants.AES_128);
        actionToken.setEncSymmetricEncryptionKey(false);

        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        List<HandlerAction> actions = new ArrayList<>();
        actions.add(new HandlerAction(WSConstants.ENCR, actionToken));
        handler.send(
            doc,
            reqData,
            actions,
            true
        );

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        SecretKeyCallbackHandler secretKeyCallbackHandler = new SecretKeyCallbackHandler();
        byte[] encodedBytes = KeyUtils.generateDigest(keyData);
        String identifier = Base64.getMimeEncoder().encodeToString(encodedBytes);
        secretKeyCallbackHandler.addSecretKey(identifier, keyData);

        verify(doc, secretKeyCallbackHandler);
    }

    @Test
    public void testAsymmetricDoubleEncryption() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        java.util.Map<String, Object> messageContext = new java.util.TreeMap<String, Object>();
        messageContext.put(
            WSHandlerConstants.PW_CALLBACK_REF, new KeystoreCallbackHandler()
        );
        reqData.setMsgContext(messageContext);

        EncryptionActionToken actionToken = new EncryptionActionToken();
        actionToken.setUser("wss40");
        actionToken.setCryptoProperties("wss40.properties");

        EncryptionActionToken actionToken2 = new EncryptionActionToken();
        actionToken2.setUser("16c73ab6-b892-458f-abf5-2f875f74882e");
        actionToken2.setCryptoProperties("crypto.properties");
        WSEncryptionPart encP =
            new WSEncryptionPart("Timestamp", WSConstants.WSU_NS, "");
        actionToken2.setParts(Collections.singletonList(encP));

        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        List<HandlerAction> actions = new ArrayList<>();
        actions.add(new HandlerAction(WSConstants.ENCR, actionToken));
        actions.add(new HandlerAction(WSConstants.TS, null));
        actions.add(new HandlerAction(WSConstants.ENCR, actionToken2));
        handler.send(
            doc,
            reqData,
            actions,
            true
        );

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        // Not verifying due to two separate Crypto instances...
    }

    @Test
    public void testMixedDoubleEncryption() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        java.util.Map<String, Object> messageContext = new java.util.TreeMap<String, Object>();
        messageContext.put(
            WSHandlerConstants.PW_CALLBACK_REF, new KeystoreCallbackHandler()
        );
        reqData.setMsgContext(messageContext);

        EncryptionActionToken actionToken = new EncryptionActionToken();
        actionToken.setUser("wss40");
        actionToken.setCryptoProperties("wss40.properties");

        EncryptionActionToken actionToken2 = new EncryptionActionToken();
        actionToken2.setKeyIdentifierId(WSConstants.ENCRYPTED_KEY_SHA1_IDENTIFIER);
        actionToken2.setKey(keyData);
        actionToken2.setSymmetricAlgorithm(WSConstants.AES_128);
        actionToken2.setEncSymmetricEncryptionKey(false);
        WSEncryptionPart encP =
            new WSEncryptionPart("Timestamp", WSConstants.WSU_NS, "");
        actionToken2.setParts(Collections.singletonList(encP));

        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        List<HandlerAction> actions = new ArrayList<>();
        actions.add(new HandlerAction(WSConstants.ENCR, actionToken));
        actions.add(new HandlerAction(WSConstants.TS, null));
        actions.add(new HandlerAction(WSConstants.ENCR, actionToken2));
        handler.send(
            doc,
            reqData,
            actions,
            true
        );

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        SecretKeyCallbackHandler secretKeyCallbackHandler = new SecretKeyCallbackHandler();
        byte[] encodedBytes = KeyUtils.generateDigest(keyData);
        String identifier = Base64.getMimeEncoder().encodeToString(encodedBytes);
        secretKeyCallbackHandler.addSecretKey(identifier, keyData);

        CombinedCallbackHandler combinedCallbackHandler =
            new CombinedCallbackHandler(secretKeyCallbackHandler, new KeystoreCallbackHandler());

        verify(doc, combinedCallbackHandler);
    }

    // Using the same key for signature + encryption here for convenience...
    @Test
    public void testAsymmetricSignatureEncryption() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        java.util.Map<String, Object> messageContext = new java.util.TreeMap<String, Object>();
        messageContext.put(
            WSHandlerConstants.PW_CALLBACK_REF, new KeystoreCallbackHandler()
        );
        reqData.setMsgContext(messageContext);

        SignatureActionToken actionToken = new SignatureActionToken();
        actionToken.setUser("wss40");
        actionToken.setCryptoProperties("wss40.properties");
        actionToken.setKeyIdentifierId(WSConstants.BST_DIRECT_REFERENCE);

        EncryptionActionToken actionToken2 = new EncryptionActionToken();
        actionToken2.setUser("wss40");
        actionToken2.setCryptoProperties("wss40.properties");

        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        List<HandlerAction> actions = new ArrayList<>();
        actions.add(new HandlerAction(WSConstants.SIGN, actionToken));
        actions.add(new HandlerAction(WSConstants.ENCR, actionToken2));
        handler.send(
            doc,
            reqData,
            actions,
            true
        );

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        verify(doc, new KeystoreCallbackHandler());
    }

    @Test
    public void testSymmetricSignatureEncryption() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        java.util.Map<String, Object> messageContext = new java.util.TreeMap<String, Object>();
        messageContext.put(
            WSHandlerConstants.PW_CALLBACK_REF, new KeystoreCallbackHandler()
        );
        reqData.setMsgContext(messageContext);

        EncryptionActionToken actionToken = new EncryptionActionToken();
        actionToken.setKey(keyData);
        actionToken.setSymmetricAlgorithm(WSConstants.AES_128);
        actionToken.setKeyIdentifierId(WSConstants.SKI_KEY_IDENTIFIER);
        actionToken.setUser("wss40");
        actionToken.setCryptoProperties("wss40.properties");
        actionToken.setTokenId(IDGenerator.generateID("EK-"));

        SignatureActionToken actionToken2 = new SignatureActionToken();
        actionToken2.setKeyIdentifierId(WSConstants.CUSTOM_SYMM_SIGNING);
        actionToken2.setKey(keyData);
        actionToken2.setSignatureAlgorithm(SignatureMethod.HMAC_SHA1);
        actionToken2.setTokenType(WSConstants.WSS_ENC_KEY_VALUE_TYPE);
        actionToken2.setTokenId(actionToken.getTokenId());

        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        List<HandlerAction> actions = new ArrayList<>();
        actions.add(new HandlerAction(WSConstants.SIGN, actionToken2));
        actions.add(new HandlerAction(WSConstants.ENCR, actionToken));
        handler.send(
            doc,
            reqData,
            actions,
            true
        );

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        verify(doc, new KeystoreCallbackHandler());
    }

    @Test
    public void testSymmetricSignatureEncryptionResponse() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        java.util.Map<String, Object> messageContext = new java.util.TreeMap<String, Object>();
        messageContext.put(
            WSHandlerConstants.PW_CALLBACK_REF, new KeystoreCallbackHandler()
        );
        reqData.setMsgContext(messageContext);

        EncryptionActionToken actionToken = new EncryptionActionToken();
        actionToken.setKey(keyData);
        actionToken.setSymmetricAlgorithm(WSConstants.AES_128);
        actionToken.setKeyIdentifierId(WSConstants.ENCRYPTED_KEY_SHA1_IDENTIFIER);
        actionToken.setEncSymmetricEncryptionKey(false);

        SignatureActionToken actionToken2 = new SignatureActionToken();
        actionToken2.setKeyIdentifierId(WSConstants.ENCRYPTED_KEY_SHA1_IDENTIFIER);
        actionToken2.setKey(keyData);
        actionToken2.setSignatureAlgorithm(SignatureMethod.HMAC_SHA1);

        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        List<HandlerAction> actions = new ArrayList<>();
        actions.add(new HandlerAction(WSConstants.SIGN, actionToken2));
        actions.add(new HandlerAction(WSConstants.ENCR, actionToken));
        handler.send(
            doc,
            reqData,
            actions,
            true
        );

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        SecretKeyCallbackHandler secretKeyCallbackHandler = new SecretKeyCallbackHandler();
        byte[] encodedBytes = KeyUtils.generateDigest(keyData);
        String identifier = Base64.getMimeEncoder().encodeToString(encodedBytes);
        secretKeyCallbackHandler.addSecretKey(identifier, keyData);

        verify(doc, secretKeyCallbackHandler);
    }

    private WSHandlerResult verify(
        Document doc, CallbackHandler callbackHandler
    ) throws Exception {
        return secEngine.processSecurityHeader(doc, null, callbackHandler, crypto);
    }


}
