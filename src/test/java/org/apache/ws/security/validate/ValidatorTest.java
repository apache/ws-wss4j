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

package org.apache.ws.security.validate;

import java.security.cert.X509Certificate;
import java.util.List;

import javax.security.auth.callback.CallbackHandler;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.common.SAML1CallbackHandler;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.common.UsernamePasswordCallbackHandler;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.components.crypto.CryptoType;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.WSSecSignature;
import org.apache.ws.security.message.WSSecTimestamp;
import org.apache.ws.security.message.WSSecUsernameToken;
import org.apache.ws.security.message.token.BinarySecurity;
import org.apache.ws.security.message.token.X509Security;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.apache.ws.security.saml.ext.SAMLParms;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;

/**
 * A test-case for Validators, check for non-standard behaviour by plugging in
 * Validator implementations.
 */
public class ValidatorTest extends org.junit.Assert {
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(ValidatorTest.class);
    private WSSecurityEngine secEngine = new WSSecurityEngine();

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
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(createdDoc);
            LOG.debug(outputString);
        }
        
        // The default behaviour is that the Timestamp validation will fail
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        try {
            verify(createdDoc, wssConfig, null, null);
            fail("Expected failure on an expired timestamp");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.MESSAGE_EXPIRED); 
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
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        // The default behaviour is that trust verification will fail
        Crypto cryptoCA = CryptoFactory.getInstance("crypto.properties");
        // Turn off BSP spec compliance
        WSSecurityEngine newEngine = new WSSecurityEngine();
        WSSConfig config = WSSConfig.getNewInstance();
        config.setWsiBSPCompliant(false);
        newEngine.setWssConfig(config);
        try {
            newEngine.processSecurityHeader(signedDoc, null, null, cryptoCA);
            fail("Failure expected on issuer serial");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.FAILED_AUTHENTICATION);
            // expected
        }
        
        // Now switch out the default signature validator
        config.setValidator(WSSecurityEngine.SIGNATURE, NoOpValidator.class);
        newEngine.setWssConfig(config);
        newEngine.processSecurityHeader(signedDoc, null, null, cryptoCA);
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
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        // The default behaviour is that password verification will fail
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        try {
            verify(signedDoc, wssConfig, new UsernamePasswordCallbackHandler(), null);
            fail("Failure expected on a bad password text");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.FAILED_AUTHENTICATION);
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
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        
        WSSConfig config = WSSConfig.getNewInstance();
        config.setValidator(WSSecurityEngine.BINARY_TOKEN, new BSTValidator());
        WSSecurityEngine secEngine = new WSSecurityEngine();
        secEngine.setWssConfig(config);
        List<WSSecurityEngineResult> results = 
            secEngine.processSecurityHeader(doc, null, null, crypto);
        
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.BST);
        BinarySecurity token =
            (BinarySecurity)actionResult.get(WSSecurityEngineResult.TAG_BINARY_SECURITY_TOKEN);
        assertTrue(token != null);
        
        AssertionWrapper assertion = 
            (AssertionWrapper)actionResult.get(WSSecurityEngineResult.TAG_TRANSFORMED_TOKEN);
        assertTrue(assertion != null);
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
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
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
        List<WSSecurityEngineResult> results = 
            secEngine.processSecurityHeader(doc, null, null, crypto);
        
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.BST);
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
    private java.util.List<WSSecurityEngineResult> verify(
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
                throw new WSSecurityException(WSSecurityException.FAILURE);
            }

            try {
                SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
                callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
                callbackHandler.setIssuer("www.example.com");
                
                SAMLParms samlParms = new SAMLParms();
                samlParms.setCallbackHandler(callbackHandler);
                AssertionWrapper assertion = new AssertionWrapper(samlParms);
    
                credential.setTransformedToken(assertion);
                return credential;
            } catch (Exception ex) {
                throw new WSSecurityException(WSSecurityException.FAILURE);
            }
        }
        
    }
    
    
}
