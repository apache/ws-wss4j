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

package org.apache.ws.security.message;

import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.common.KeystoreCallbackHandler;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.common.SecretKeyCallbackHandler;
import org.apache.ws.security.components.crypto.AlgorithmSuite;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.ws.security.util.XMLUtils;
import org.apache.xml.security.utils.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;


/**
 * A set of test-cases for encrypting and decrypting SOAP requests when specifying an 
 * AlgorithmSuite policy.
 */
public class EncryptionAlgorithmSuiteTest extends org.junit.Assert {
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(EncryptionAlgorithmSuiteTest.class);
    
    private Crypto crypto = null;
    
    public EncryptionAlgorithmSuiteTest() throws Exception {
        WSSConfig.init();
        crypto = CryptoFactory.getInstance("wss40.properties");
    }

    @org.junit.Test
    public void testEncryption() throws Exception {
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setUserInfo("wss40");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        builder.setSymmetricEncAlgorithm(WSConstants.TRIPLE_DES);
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document encryptedDoc = builder.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(encryptedDoc);
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
            // expected
        }
    }
    
    @org.junit.Test
    public void testEncryptionKeyTransportRSA15() throws Exception {
        
        Crypto wssCrypto = CryptoFactory.getInstance("wss40.properties");
        
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setUserInfo("wss40");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        builder.setSymmetricEncAlgorithm(WSConstants.TRIPLE_DES);
        builder.setKeyEncAlgo(WSConstants.KEYTRANSPORT_RSA15);
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document encryptedDoc = builder.build(doc, wssCrypto, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }
        
        Element securityHeader = WSSecurityUtil.getSecurityHeader(encryptedDoc, null);
        AlgorithmSuite algorithmSuite = createAlgorithmSuite();
        
        try {
            verify(securityHeader, algorithmSuite, wssCrypto);
            fail("Expected failure as RSA 15 is not allowed");
        } catch (WSSecurityException ex) {
            // expected
        }
        
        algorithmSuite.addKeyWrapAlgorithm(WSConstants.KEYTRANSPORT_RSA15);
        verify(securityHeader, algorithmSuite, wssCrypto);
    }
    
    @org.junit.Test
    public void testEncryptionMethodAES128() throws Exception {
        
        Crypto wssCrypto = CryptoFactory.getInstance("wss40.properties");
        
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setUserInfo("wss40");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        builder.setSymmetricEncAlgorithm(WSConstants.AES_128);
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document encryptedDoc = builder.build(doc, wssCrypto, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }
        
        Element securityHeader = WSSecurityUtil.getSecurityHeader(encryptedDoc, null);
        AlgorithmSuite algorithmSuite = createAlgorithmSuite();
        
        try {
            verify(securityHeader, algorithmSuite, wssCrypto);
            fail("Expected failure as AES 128 is not allowed");
        } catch (WSSecurityException ex) {
            // expected
        }
        
        algorithmSuite.addEncryptionMethod(WSConstants.AES_128);
        verify(securityHeader, algorithmSuite, wssCrypto);
    }
    
    @org.junit.Test
    public void testSymmetricEncryption() throws Exception {
        
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey key = keyGen.generateKey();
        byte[] keyData = key.getEncoded();
        
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setKeyIdentifierType(WSConstants.ENCRYPTED_KEY_SHA1_IDENTIFIER);
        builder.setSymmetricKey(key);
        builder.setEncryptSymmKey(false);
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document encryptedDoc = builder.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }
        
        byte[] encodedBytes = WSSecurityUtil.generateDigest(keyData);
        String identifier = Base64.encode(encodedBytes);
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
            // expected
        }
        
        algorithmSuite.setMinimumSymmetricKeyLength(64);
        algorithmSuite.setMaximumSymmetricKeyLength(120);
        try {
            secEngine.processSecurityHeader(securityHeader, data);
            fail("Expected failure as a 128 bit key is not allowed");
        } catch (WSSecurityException ex) {
            // expected
        }
    }
    
    
    private AlgorithmSuite createAlgorithmSuite() {
        AlgorithmSuite algorithmSuite = new AlgorithmSuite();
        algorithmSuite.setMinimumAsymmetricKeyLength(512);
        algorithmSuite.addKeyWrapAlgorithm(WSConstants.KEYTRANSPORT_RSAOEP);
        algorithmSuite.addEncryptionMethod(WSConstants.TRIPLE_DES);
        
        return algorithmSuite;
    }

    private List<WSSecurityEngineResult> verify(
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
