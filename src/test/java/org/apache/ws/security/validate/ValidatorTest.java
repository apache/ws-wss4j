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

import javax.security.auth.callback.CallbackHandler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.common.UsernamePasswordCallbackHandler;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.WSSecSignature;
import org.apache.ws.security.message.WSSecTimestamp;
import org.apache.ws.security.message.WSSecUsernameToken;
import org.w3c.dom.Document;

/**
 * A test-case for Validators, check for non-standard behaviour by plugging in
 * Validator implementations.
 */
public class ValidatorTest extends org.junit.Assert {
    private static final Log LOG = LogFactory.getLog(ValidatorTest.class);
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
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        try {
            verify(signedDoc, wssConfig, null, cryptoCA);
            throw new Exception("Failure expected on issuer serial");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.FAILED_AUTHENTICATION);
            // expected
        }
        
        // Now switch out the default signature validator
        wssConfig.setValidator(WSSecurityEngine.SIGNATURE, NoOpValidator.class);
        verify(signedDoc, wssConfig, null, cryptoCA);
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
    
    
}
