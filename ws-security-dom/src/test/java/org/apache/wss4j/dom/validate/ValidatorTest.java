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

package org.apache.wss4j.dom.validate;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import javax.security.auth.callback.CallbackHandler;

import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SAMLCallback;
import org.apache.wss4j.common.saml.SAMLUtil;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.token.BinarySecurity;
import org.apache.wss4j.common.token.X509Security;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSSConfig;
import org.apache.wss4j.dom.WSSecurityEngine;
import org.apache.wss4j.dom.WSSecurityEngineResult;
import org.apache.wss4j.dom.common.SAML1CallbackHandler;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.dom.common.UsernamePasswordCallbackHandler;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecSignature;
import org.apache.wss4j.dom.message.WSSecTimestamp;
import org.apache.wss4j.dom.message.WSSecUsernameToken;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.w3c.dom.Document;

/**
 * A test-case for Validators, check for non-standard behaviour by plugging in
 * Validator implementations.
 */
public class ValidatorTest extends org.junit.Assert {
    private static final org.slf4j.Logger LOG = 
        org.slf4j.LoggerFactory.getLogger(ValidatorTest.class);
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    
    @org.junit.AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }

    /**
     * This is a test for processing an expired Timestamp.
     */
    @org.junit.Test
    public void testExpiredTimestamp() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        WSSecTimestamp timestamp = new WSSecTimestamp();
        timestamp.setTimeToLive(-1);
        Document createdDoc = timestamp.build(doc, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(createdDoc);
            LOG.debug(outputString);
        }
        
        // The default behaviour is that the Timestamp validation will fail
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        try {
            verify(createdDoc, wssConfig, null, null);
            fail("Expected failure on an expired timestamp");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.MESSAGE_EXPIRED); 
        }

        // Now switch out the default Timestamp validator
        wssConfig.setValidator(WSSecurityEngine.TIMESTAMP, NoOpValidator.class);
        verify(createdDoc, wssConfig, null, null);
    }
    
    /**
     * Test for processing an untrusted signature
     */
    @org.junit.Test
    public void testUntrustedSignature() throws Exception {
        WSSecSignature sign = new WSSecSignature();
        sign.setUserInfo("wss40", "security");
        sign.setKeyIdentifierType(WSConstants.X509_KEY_IDENTIFIER);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Crypto crypto = CryptoFactory.getInstance("wss40.properties");
        Document signedDoc = sign.build(doc, crypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        // The default behaviour is that trust verification will fail
        Crypto cryptoCA = CryptoFactory.getInstance("crypto.properties");
        // Turn off BSP spec compliance
        WSSecurityEngine newEngine = new WSSecurityEngine();
        RequestData data = new RequestData();
        data.setSigVerCrypto(cryptoCA);
        data.setIgnoredBSPRules(Collections.singletonList(BSPRule.R3063));
        try {
            newEngine.processSecurityHeader(signedDoc, data);
            fail("Failure expected on issuer serial");
        } catch (WSSecurityException ex) {
            // expected
        }
        
        // Now switch out the default signature validator
        WSSConfig config = WSSConfig.getNewInstance();
        config.setValidator(WSSecurityEngine.SIGNATURE, NoOpValidator.class);
        newEngine.setWssConfig(config);
        data.setWssConfig(config);
        newEngine.processSecurityHeader(signedDoc, data);
    }
    
    /**
     * Test that adds a UserNameToken with (bad) password text to a WS-Security envelope
     */
    @org.junit.Test
    public void testUsernameTokenBadText() throws Exception {
        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setPasswordType(WSConstants.PASSWORD_TEXT);
        builder.setUserInfo("wernerd", "verySecre");
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, secHeader);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        // The default behaviour is that password verification will fail
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        try {
            verify(signedDoc, wssConfig, new UsernamePasswordCallbackHandler(), null);
            fail("Failure expected on a bad password text");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
            // expected
        }
        
        // Now switch out the default UsernameToken validator
        wssConfig.setValidator(WSSecurityEngine.USERNAME_TOKEN, NoOpValidator.class);
        verify(signedDoc, wssConfig, new UsernamePasswordCallbackHandler(), null);
    }
    
    /**
     * In this test, a BinarySecurityToken is added to the SOAP header. A custom processor
     * validates the BST and transforms it into a SAML Assertion.
     */
    @org.junit.Test
    public void testTransformedBST() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        X509Security bst = new X509Security(doc);
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("wss40");
        Crypto crypto = CryptoFactory.getInstance("wss40.properties");
        X509Certificate[] certs = crypto.getX509Certificates(cryptoType);
        bst.setX509Certificate(certs[0]);
        
        WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), bst.getElement());
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("BST output");
            String outputString = 
                XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        
        WSSConfig config = WSSConfig.getNewInstance();
        config.setValidator(WSSecurityEngine.BINARY_TOKEN, new BSTValidator());
        WSSecurityEngine secEngine = new WSSecurityEngine();
        secEngine.setWssConfig(config);
        WSHandlerResult results = 
            secEngine.processSecurityHeader(doc, null, null, crypto);
        
        List<WSSecurityEngineResult> bstResults = 
            results.getActionResults().get(WSConstants.BST);
        WSSecurityEngineResult actionResult = bstResults.get(0);

        BinarySecurity token =
            (BinarySecurity)actionResult.get(WSSecurityEngineResult.TAG_BINARY_SECURITY_TOKEN);
        assertTrue(token != null);
        
        SamlAssertionWrapper samlAssertion =
            (SamlAssertionWrapper)actionResult.get(WSSecurityEngineResult.TAG_TRANSFORMED_TOKEN);
        assertTrue(samlAssertion != null);
    }
    
    /**
     * In this test, a SOAP request is constructed where the SOAP body is signed via a 
     * BinarySecurityToken. The receiving side does not trust the BST, and so the test fails.
     * The second time, a custom Validator (NoOpValidator for this case) is installed for the
     * BST, and so trust verification passes on the Signature. 
     */
    @org.junit.Test
    public void testValidatedBSTSignature() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, CryptoFactory.getInstance(), secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        Crypto crypto = CryptoFactory.getInstance("wss40.properties");
        WSSConfig config = WSSConfig.getNewInstance();
        WSSecurityEngine secEngine = new WSSecurityEngine();
        secEngine.setWssConfig(config);
        try {
            secEngine.processSecurityHeader(doc, null, null, crypto);
            fail("Expected failure on untrusted signature");
        } catch (WSSecurityException ex) {
            // expected
        }
        
        config.setValidator(WSSecurityEngine.BINARY_TOKEN, new BSTValidator());
        WSHandlerResult results = 
            secEngine.processSecurityHeader(doc, null, null, crypto);
        
        List<WSSecurityEngineResult> bstResults = 
            results.getActionResults().get(WSConstants.BST);
        WSSecurityEngineResult actionResult = bstResults.get(0);
        
        BinarySecurity token =
            (BinarySecurity)actionResult.get(WSSecurityEngineResult.TAG_BINARY_SECURITY_TOKEN);
        assertTrue(token != null);
    }


    /**
     * Verifies the soap envelope
     * 
     * @param env soap envelope
     * @param wssConfig
     * @throws java.lang.Exception Thrown when there is a problem in verification
     */
    private WSHandlerResult verify(
        Document doc, WSSConfig wssConfig, CallbackHandler cb, Crypto crypto
    ) throws Exception {
        secEngine.setWssConfig(wssConfig);
        return secEngine.processSecurityHeader(doc, null, cb, crypto);
    }
    
    
    /**
     * A validator for a BST token.
     */
    private static class BSTValidator implements Validator {

        public Credential validate(Credential credential, RequestData data) throws WSSecurityException {
            BinarySecurity token = credential.getBinarySecurityToken();
            if (token == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE);
            }

            try {
                SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
                callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
                callbackHandler.setIssuer("www.example.com");
                
                SAMLCallback samlCallback = new SAMLCallback();
                SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
                SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);
    
                credential.setTransformedToken(samlAssertion);
                return credential;
            } catch (Exception ex) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE);
            }
        }
        
    }
    
    
}
