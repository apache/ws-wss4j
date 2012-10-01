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
import javax.xml.crypto.dsig.SignatureMethod;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
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
 * A set of test-cases for signing and verifying SOAP requests when specifying an 
 * AlgorithmSuite policy.
 */
public class SignatureAlgorithmSuiteTest extends org.junit.Assert {
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(SignatureAlgorithmSuiteTest.class);
    
    private Crypto crypto = null;
    
    public SignatureAlgorithmSuiteTest() throws Exception {
        WSSConfig.init();
        crypto = CryptoFactory.getInstance();
    }

    @org.junit.Test
    public void testSignature() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        builder.setSignatureAlgorithm(WSConstants.RSA_SHA1);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        Element securityHeader = WSSecurityUtil.getSecurityHeader(signedDoc, null);
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
    public void testSignatureMethodDSA() throws Exception {
        Crypto dsaCrypto = CryptoFactory.getInstance("wss40.properties");
        
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("wss40DSA", "security");
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        builder.setSignatureAlgorithm(WSConstants.DSA);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, dsaCrypto, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        Element securityHeader = WSSecurityUtil.getSecurityHeader(signedDoc, null);
        AlgorithmSuite algorithmSuite = createAlgorithmSuite();
        
        try {
            verify(securityHeader, algorithmSuite, dsaCrypto);
            fail("Expected failure as DSA is not allowed");
        } catch (WSSecurityException ex) {
            // expected
        }
        
        algorithmSuite.addSignatureMethod(WSConstants.DSA);
        verify(securityHeader, algorithmSuite, dsaCrypto);
    }
    
    @org.junit.Test
    public void testSymmetricKey() throws Exception {
        
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey key = keyGen.generateKey();
        byte[] keyData = key.getEncoded();
        
        WSSecSignature builder = new WSSecSignature();
        builder.setKeyIdentifierType(WSConstants.ENCRYPTED_KEY_SHA1_IDENTIFIER);
        builder.setSecretKey(keyData);
        builder.setSignatureAlgorithm(SignatureMethod.HMAC_SHA1);
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        byte[] encodedBytes = WSSecurityUtil.generateDigest(keyData);
        String identifier = Base64.encode(encodedBytes);
        SecretKeyCallbackHandler secretKeyCallbackHandler = new SecretKeyCallbackHandler();
        secretKeyCallbackHandler.addSecretKey(identifier, keyData);
        
        Element securityHeader = WSSecurityUtil.getSecurityHeader(signedDoc, null);
        AlgorithmSuite algorithmSuite = createAlgorithmSuite();
        
        WSSecurityEngine secEngine = new WSSecurityEngine();
        RequestData data = new RequestData();
        data.setSigCrypto(crypto);
        data.setCallbackHandler(secretKeyCallbackHandler);
        data.setAlgorithmSuite(algorithmSuite);
        
        try {
            secEngine.processSecurityHeader(securityHeader, data);
            fail("Expected failure as HMAC-SHA1 is not allowed");
        } catch (WSSecurityException ex) {
            // expected
        }
        
        algorithmSuite.addSignatureMethod(WSConstants.HMAC_SHA1);
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
    
    @org.junit.Test
    public void testC14nMethod() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        builder.setSignatureAlgorithm(WSConstants.RSA_SHA1);
        builder.setSigCanonicalization(WSConstants.C14N_EXCL_WITH_COMMENTS);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        Element securityHeader = WSSecurityUtil.getSecurityHeader(signedDoc, null);
        AlgorithmSuite algorithmSuite = createAlgorithmSuite();
        
        try {
            verify(securityHeader, algorithmSuite, crypto);
            fail("Expected failure as C14n algorithm is not allowed");
        } catch (WSSecurityException ex) {
            // expected
        }
        
        algorithmSuite.addC14nAlgorithm(WSConstants.C14N_EXCL_WITH_COMMENTS);
        verify(securityHeader, algorithmSuite, crypto);
    }
    
    @org.junit.Test
    public void testDigestMethod() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        builder.setSignatureAlgorithm(WSConstants.RSA_SHA1);
        builder.setDigestAlgo(WSConstants.SHA256);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        Element securityHeader = WSSecurityUtil.getSecurityHeader(signedDoc, null);
        AlgorithmSuite algorithmSuite = createAlgorithmSuite();
        
        try {
            verify(securityHeader, algorithmSuite, crypto);
            fail("Expected failure as Digest algorithm is not allowed");
        } catch (WSSecurityException ex) {
            // expected
        }
        
        algorithmSuite.addDigestAlgorithm(WSConstants.SHA256);
        verify(securityHeader, algorithmSuite, crypto);
    }
    
    private AlgorithmSuite createAlgorithmSuite() {
        AlgorithmSuite algorithmSuite = new AlgorithmSuite();
        algorithmSuite.addSignatureMethod(WSConstants.RSA_SHA1);
        algorithmSuite.setMinimumAsymmetricKeyLength(512);
        algorithmSuite.addC14nAlgorithm(WSConstants.C14N_EXCL_OMIT_COMMENTS);
        algorithmSuite.addDigestAlgorithm(WSConstants.SHA1);
        
        return algorithmSuite;
    }

    private List<WSSecurityEngineResult> verify(
        Element securityHeader, AlgorithmSuite algorithmSuite, Crypto sigVerCrypto
    ) throws Exception {
        WSSecurityEngine secEngine = new WSSecurityEngine();
        RequestData data = new RequestData();
        data.setSigCrypto(sigVerCrypto);
        
        data.setAlgorithmSuite(algorithmSuite);
        
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        wssConfig.setWsiBSPCompliant(false);
        data.setWssConfig(wssConfig);
        
        return secEngine.processSecurityHeader(securityHeader, data);
    }

}
