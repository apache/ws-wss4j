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

package org.apache.wss4j.dom.message;

import java.io.IOException;
import java.util.Collections;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.crypto.dsig.SignatureMethod;

import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.common.CustomHandler;
import org.apache.wss4j.dom.common.KeystoreCallbackHandler;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.common.SecretKeyCallbackHandler;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.util.KeyUtils;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.handler.HandlerAction;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Document;


/**
 * Test symmetric key signature created using an encrypted key
 * Demonstrates that Signature Crypto object can have null values when
 * calling processSecurityHeader method of WSSecurityEngine.
 */
public class SymmetricSignatureTest extends org.junit.Assert implements CallbackHandler {
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(SymmetricSignatureTest.class);
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private CallbackHandler callbackHandler = new KeystoreCallbackHandler();
    private SecretKeyCallbackHandler secretKeyCallbackHandler = new SecretKeyCallbackHandler();
    private byte[] keyData;
    private Crypto crypto;

    @org.junit.AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }

    public SymmetricSignatureTest() throws Exception {
        WSSConfig.init();
        crypto = CryptoFactory.getInstance("wss40.properties");
    }

    /**
     * Setup method
     * <p/>
     *
     * @throws Exception Thrown when there is a problem in setup
     */
    @Before
    public void setUp() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey key = keyGen.generateKey();
        keyData = key.getEncoded();
    }

    /**
     * Test signing a message body using a symmetric key with EncryptedKeySHA1
     */
    @Test
    public void testSymmetricSignatureSHA1() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecSignature sign = new WSSecSignature(secHeader);
        sign.setKeyIdentifierType(WSConstants.ENCRYPTED_KEY_SHA1_IDENTIFIER);
        sign.setSecretKey(keyData);
        sign.setSignatureAlgorithm(SignatureMethod.HMAC_SHA1);

        Document signedDoc = sign.build(crypto);

        byte[] encodedBytes = KeyUtils.generateDigest(keyData);
        String identifier = org.apache.xml.security.utils.XMLUtils.encodeToString(encodedBytes);
        secretKeyCallbackHandler.addSecretKey(identifier, keyData);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed symmetric message SHA1:");
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        secEngine.processSecurityHeader(doc, null, secretKeyCallbackHandler, null, crypto);
    }


    /**
     * Test signing a message body using a symmetric key with Direct Reference to an
     * EncryptedKey
     */
    @Test
    public void testSymmetricSignatureDR() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecEncryptedKey encrKey = new WSSecEncryptedKey(secHeader);
        encrKey.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        encrKey.setUserInfo("wss40", "security");
        encrKey.setSymmetricEncAlgorithm(WSConstants.AES_192);
        encrKey.prepare(crypto);

        WSSecSignature sign = new WSSecSignature(secHeader);
        sign.setKeyIdentifierType(WSConstants.CUSTOM_SYMM_SIGNING);
        sign.setCustomTokenId(encrKey.getId());
        sign.setSecretKey(encrKey.getEphemeralKey());
        sign.setSignatureAlgorithm(SignatureMethod.HMAC_SHA1);
        sign.setCustomTokenValueType(WSConstants.WSS_ENC_KEY_VALUE_TYPE);

        Document signedDoc = sign.build(crypto);
        encrKey.prependToHeader();

        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed symmetric message DR:");
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        verify(signedDoc);
    }

    /**
     * Test that first signs, then encrypts a WS-Security envelope.
     * <p/>
     *
     * @throws Exception Thrown when there is any problem in signing, encryption,
     *                   decryption, or verification
     */
    @Test
    public void testEncryptedKeySignature() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        LOG.info("Before Sign/Encryption....");

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecEncryptedKey encrKey = new WSSecEncryptedKey(secHeader);
        encrKey.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        encrKey.setUserInfo("wss40", "security");
        encrKey.setSymmetricEncAlgorithm(WSConstants.AES_192);
        encrKey.prepare(crypto);

        WSSecEncrypt encrypt = new WSSecEncrypt(secHeader);
        encrypt.setEncKeyId(encrKey.getId());
        encrypt.setEphemeralKey(encrKey.getEphemeralKey());
        encrypt.setSymmetricEncAlgorithm(WSConstants.TRIPLE_DES);
        encrypt.setEncryptSymmKey(false);
        encrypt.setEncryptedKeyElement(encrKey.getEncryptedKeyElement());

        WSSecSignature sign = new WSSecSignature(secHeader);
        sign.setKeyIdentifierType(WSConstants.CUSTOM_SYMM_SIGNING);
        sign.setCustomTokenId(encrKey.getId());
        sign.setCustomTokenValueType(WSConstants.WSS_ENC_KEY_VALUE_TYPE);
        sign.setSecretKey(encrKey.getEphemeralKey());
        sign.setSignatureAlgorithm(SignatureMethod.HMAC_SHA1);

        sign.build(crypto);
        Document encryptedSignedDoc = encrypt.build(crypto);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed and encrypted message with IssuerSerial key identifier (both), 3DES:");
            String outputString =
                XMLUtils.prettyDocumentToString(encryptedSignedDoc);
            LOG.debug(outputString);
        }

        LOG.info("After Sign/Encryption....");
        verify(encryptedSignedDoc);
    }

    /**
     * Test signing a message body using a symmetric key with EncryptedKeySHA1.
     * The request is generated using WSHandler, instead of coding it.
     */
    @Test
    public void testSymmetricSignatureSHA1Handler() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        java.util.Map<String, Object> messageContext = new java.util.TreeMap<>();
        messageContext.put(WSHandlerConstants.SIG_KEY_ID, "EncryptedKeySHA1");
        messageContext.put(WSHandlerConstants.SIG_ALGO, SignatureMethod.HMAC_SHA1);
        messageContext.put(WSHandlerConstants.PW_CALLBACK_REF, this);
        reqData.setMsgContext(messageContext);
        reqData.setUsername("");

        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        HandlerAction action = new HandlerAction(WSConstants.SIGN);
        handler.send(
            doc,
            reqData,
            Collections.singletonList(action),
            true
        );

        String outputString =
            XMLUtils.prettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }

        reqData = new RequestData();
        reqData.setWssConfig(WSSConfig.getNewInstance());
        messageContext = new java.util.TreeMap<>();
        messageContext.put(WSHandlerConstants.PW_CALLBACK_REF, this);
        reqData.setMsgContext(messageContext);
        reqData.setUsername("");

        handler.receive(Collections.singletonList(WSConstants.SIGN), reqData);

        secEngine.processSecurityHeader(doc, null, this, null, crypto);
    }


    /**
     * Verifies the soap envelope
     * <p/>
     *
     * @param doc
     * @throws Exception Thrown when there is a problem in verification
     */
    private void verify(Document doc) throws Exception {
        secEngine.processSecurityHeader(doc, null, callbackHandler, null, crypto);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Verfied and decrypted message:");
            String outputString =
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }
    }

    public void handle(Callback[] callbacks)
        throws IOException, UnsupportedCallbackException {
        for (int i = 0; i < callbacks.length; i++) {
            if (callbacks[i] instanceof WSPasswordCallback) {
                WSPasswordCallback pc = (WSPasswordCallback) callbacks[i];
                /*
                 * here call a function/method to lookup the password for
                 * the given identifier (e.g. a user name or keystore alias)
                 * e.g.: pc.setPassword(passStore.getPassword(pc.getIdentfifier))
                 * for Testing we supply a fixed name here.
                 */
                pc.setPassword("security");
                pc.setKey(keyData);
            } else {
                throw new UnsupportedCallbackException(callbacks[i], "Unrecognized Callback");
            }
        }
    }


}
