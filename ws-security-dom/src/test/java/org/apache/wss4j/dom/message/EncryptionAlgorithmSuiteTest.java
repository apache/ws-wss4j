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

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.apache.wss4j.common.crypto.AlgorithmSuite;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.KeyUtils;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.common.KeystoreCallbackHandler;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.common.SecretKeyCallbackHandler;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * A set of test-cases for encrypting and decrypting SOAP requests when specifying an
 * AlgorithmSuite policy.
 */
public class EncryptionAlgorithmSuiteTest {
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(EncryptionAlgorithmSuiteTest.class);

    private Crypto crypto;

    @org.junit.AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }

    public EncryptionAlgorithmSuiteTest() throws Exception {
        WSSConfig.init();
        crypto = CryptoFactory.getInstance("wss40.properties");
    }

    @Test
    public void testEncryption() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecEncrypt builder = new WSSecEncrypt(secHeader);
        builder.setUserInfo("wss40");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        builder.setSymmetricEncAlgorithm(WSConstants.TRIPLE_DES);

        KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.TRIPLE_DES);
        SecretKey symmetricKey = keyGen.generateKey();
        Document encryptedDoc = builder.build(crypto, symmetricKey);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }

        Element securityHeader = WSSecurityUtil.getSecurityHeader(encryptedDoc, null);
        AlgorithmSuite algorithmSuite = createAlgorithmSuite();

        verify(securityHeader, algorithmSuite, crypto);

        algorithmSuite.setMinimumAsymmetricKeyLength(1024);

        try {
            verify(securityHeader, algorithmSuite, crypto);
            fail("Expected failure as 512-bit keys are not allowed");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY);
        }
    }

    @Test
    public void testEncryptionKeyTransportRSA15() throws Exception {

        Crypto wssCrypto = CryptoFactory.getInstance("wss40.properties");

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecEncrypt builder = new WSSecEncrypt(secHeader);
        builder.setUserInfo("wss40");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        builder.setSymmetricEncAlgorithm(WSConstants.TRIPLE_DES);
        builder.setKeyEncAlgo(WSConstants.KEYTRANSPORT_RSA15);

        KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.TRIPLE_DES);
        SecretKey symmetricKey = keyGen.generateKey();
        Document encryptedDoc = builder.build(crypto, symmetricKey);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }

        Element securityHeader = WSSecurityUtil.getSecurityHeader(encryptedDoc, null);
        AlgorithmSuite algorithmSuite = createAlgorithmSuite();

        try {
            verify(securityHeader, algorithmSuite, wssCrypto);
            fail("Expected failure as RSA 15 is not allowed");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY);
        }

        algorithmSuite.addKeyWrapAlgorithm(WSConstants.KEYTRANSPORT_RSA15);
        verify(securityHeader, algorithmSuite, wssCrypto);
    }

    @Test
    public void testEncryptionKeyTransportRSA15NoAlgorithmSuite() throws Exception {

        Crypto wssCrypto = CryptoFactory.getInstance("wss40.properties");

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecEncrypt builder = new WSSecEncrypt(secHeader);
        builder.setUserInfo("wss40");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        builder.setSymmetricEncAlgorithm(WSConstants.TRIPLE_DES);
        builder.setKeyEncAlgo(WSConstants.KEYTRANSPORT_RSA15);

        KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.TRIPLE_DES);
        SecretKey symmetricKey = keyGen.generateKey();
        Document encryptedDoc = builder.build(crypto, symmetricKey);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }

        Element securityHeader = WSSecurityUtil.getSecurityHeader(encryptedDoc, null);

        try {
            verify(securityHeader, null, wssCrypto);
            fail("Expected failure as RSA 15 is not allowed");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY);
        }

        // Now enable RSA v1.5 processing
        WSSecurityEngine secEngine = new WSSecurityEngine();
        RequestData data = new RequestData();
        data.setDecCrypto(wssCrypto);
        data.setAllowRSA15KeyTransportAlgorithm(true);

        data.setCallbackHandler(new KeystoreCallbackHandler());

        secEngine.processSecurityHeader(securityHeader, data);
    }

    @Test
    public void testEncryptionMethodAES128() throws Exception {

        Crypto wssCrypto = CryptoFactory.getInstance("wss40.properties");

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecEncrypt builder = new WSSecEncrypt(secHeader);
        builder.setUserInfo("wss40");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        builder.setSymmetricEncAlgorithm(WSConstants.AES_128);

        KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.AES_128);
        SecretKey symmetricKey = keyGen.generateKey();
        Document encryptedDoc = builder.build(crypto, symmetricKey);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }

        Element securityHeader = WSSecurityUtil.getSecurityHeader(encryptedDoc, null);
        AlgorithmSuite algorithmSuite = createAlgorithmSuite();

        try {
            verify(securityHeader, algorithmSuite, wssCrypto);
            fail("Expected failure as AES 128 is not allowed");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY);
        }

        algorithmSuite.addEncryptionMethod(WSConstants.AES_128);
        verify(securityHeader, algorithmSuite, wssCrypto);
    }

    @Test
    public void testSymmetricEncryption() throws Exception {

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey key = keyGen.generateKey();
        byte[] keyData = key.getEncoded();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecEncrypt builder = new WSSecEncrypt(secHeader);
        builder.setKeyIdentifierType(WSConstants.ENCRYPTED_KEY_SHA1_IDENTIFIER);
        builder.setEncryptSymmKey(false);

        Document encryptedDoc = builder.build(crypto, key);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }

        byte[] encodedBytes = KeyUtils.generateDigest(keyData);
        String identifier = org.apache.xml.security.utils.XMLUtils.encodeToString(encodedBytes);
        SecretKeyCallbackHandler secretKeyCallbackHandler = new SecretKeyCallbackHandler();
        secretKeyCallbackHandler.addSecretKey(identifier, keyData);

        Element securityHeader = WSSecurityUtil.getSecurityHeader(encryptedDoc, null);
        AlgorithmSuite algorithmSuite = createAlgorithmSuite();

        WSSecurityEngine secEngine = new WSSecurityEngine();
        RequestData data = new RequestData();
        data.setDecCrypto(crypto);
        data.setCallbackHandler(secretKeyCallbackHandler);

        data.setAlgorithmSuite(algorithmSuite);

        algorithmSuite.addEncryptionMethod(WSConstants.AES_128);
        secEngine.processSecurityHeader(securityHeader, data);

        algorithmSuite.setMinimumSymmetricKeyLength(256);
        try {
            secEngine.processSecurityHeader(securityHeader, data);
            fail("Expected failure as a 128 bit key is not allowed");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY);
        }

        algorithmSuite.setMinimumSymmetricKeyLength(64);
        algorithmSuite.setMaximumSymmetricKeyLength(120);
        try {
            secEngine.processSecurityHeader(securityHeader, data);
            fail("Expected failure as a 128 bit key is not allowed");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY);
        }
    }


    private AlgorithmSuite createAlgorithmSuite() {
        AlgorithmSuite algorithmSuite = new AlgorithmSuite();
        algorithmSuite.setMinimumAsymmetricKeyLength(512);
        algorithmSuite.addKeyWrapAlgorithm(WSConstants.KEYTRANSPORT_RSAOAEP);
        algorithmSuite.addEncryptionMethod(WSConstants.TRIPLE_DES);

        return algorithmSuite;
    }

    private WSHandlerResult verify(
        Element securityHeader, AlgorithmSuite algorithmSuite, Crypto decCrypto
    ) throws Exception {
        WSSecurityEngine secEngine = new WSSecurityEngine();
        RequestData data = new RequestData();
        data.setDecCrypto(decCrypto);

        data.setAlgorithmSuite(algorithmSuite);

        data.setCallbackHandler(new KeystoreCallbackHandler());

        return secEngine.processSecurityHeader(securityHeader, data);
    }

}