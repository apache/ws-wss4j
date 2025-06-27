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

import java.util.Collections;

import javax.security.auth.callback.CallbackHandler;

import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.SOAPUtil;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.common.dom.WSConstants;

import org.apache.wss4j.dom.common.UsernamePasswordCallbackHandler;
import org.apache.wss4j.common.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.common.dom.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.common.dom.message.WSSecHeader;
import org.apache.wss4j.common.dom.message.WSSecSignature;
import org.apache.wss4j.dom.message.WSSecTimestamp;
import org.apache.wss4j.dom.message.WSSecUsernameToken;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * A test-case for Validators, check for non-standard behaviour by plugging in
 * Validator implementations.
 */
public class ValidatorTest {
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(ValidatorTest.class);
    private WSSecurityEngine secEngine = new WSSecurityEngine();

    /**
     * This is a test for processing an expired Timestamp.
     */
    @Test
    public void testExpiredTimestamp() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecTimestamp timestamp = new WSSecTimestamp(secHeader);
        timestamp.setTimeToLive(-1);
        Document createdDoc = timestamp.build();

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(createdDoc);
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
        wssConfig.setValidator(WSConstants.TIMESTAMP, NoOpValidator.class);
        verify(createdDoc, wssConfig, null, null);
    }

    /**
     * Test for processing an untrusted signature
     */
    @Test
    public void testUntrustedSignature() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecSignature sign = new WSSecSignature(secHeader);
        sign.setUserInfo("wss40", "security");
        sign.setKeyIdentifierType(WSConstants.X509_KEY_IDENTIFIER);

        Crypto crypto = CryptoFactory.getInstance("wss40.properties");
        Document signedDoc = sign.build(crypto);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
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
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.FAILURE);
        }

        // Now switch out the default signature validator
        WSSConfig config = WSSConfig.getNewInstance();
        config.setValidator(WSConstants.SIGNATURE, NoOpValidator.class);
        newEngine.setWssConfig(config);
        data.setWssConfig(config);
        newEngine.processSecurityHeader(signedDoc, data);
    }

    /**
     * Test that adds a UserNameToken with (bad) password text to a WS-Security envelope
     */
    @Test
    public void testUsernameTokenBadText() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecUsernameToken builder = new WSSecUsernameToken(secHeader);
        builder.setPasswordType(WSConstants.PASSWORD_TEXT);
        builder.setUserInfo("wernerd", "verySecre");

        Document signedDoc = builder.build();

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        // The default behaviour is that password verification will fail
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        try {
            verify(signedDoc, wssConfig, new UsernamePasswordCallbackHandler(), null);
            fail("Failure expected on a bad password text");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
        }

        // Now switch out the default UsernameToken validator
        wssConfig.setValidator(WSConstants.USERNAME_TOKEN, NoOpValidator.class);
        verify(signedDoc, wssConfig, new UsernamePasswordCallbackHandler(), null);
    }


    /**
     * Verifies the soap envelope
     *
     * @param doc soap document
     * @param wssConfig
     * @throws Exception Thrown when there is a problem in verification
     */
    private WSHandlerResult verify(
        Document doc, WSSConfig wssConfig, CallbackHandler cb, Crypto crypto
    ) throws Exception {
        secEngine.setWssConfig(wssConfig);
        return secEngine.processSecurityHeader(doc, null, cb, crypto);
    }

}