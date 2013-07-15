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

import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSSConfig;
import org.apache.wss4j.dom.WSSecurityEngineResult;
import org.apache.wss4j.dom.WSSecurityEngine;
import org.apache.wss4j.dom.common.CustomHandler;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.dom.common.UsernamePasswordCallbackHandler;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.w3c.dom.Document;

import javax.security.auth.callback.CallbackHandler;

import java.util.List;

/**
 * WS-Security Test Case for UsernameToken Key Derivation, as defined in the 
 * UsernameTokenProfile 1.1 specification. The derived keys are used for signature.
 * Note that this functionality is different to the UTDerivedKeyTest test case,
 * which uses the derived key in conjunction with wsc:DerivedKeyToken. It's also
 * different to UTWseSignatureTest, which derives a key for signature using a 
 * non-standard implementation.
 */
public class UTSignatureTest extends org.junit.Assert {
    private static final org.slf4j.Logger LOG = 
        org.slf4j.LoggerFactory.getLogger(UTSignatureTest.class);
    private CallbackHandler callbackHandler = new UsernamePasswordCallbackHandler();
    private Crypto crypto = null;
    
    @org.junit.AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }
    
    public UTSignatureTest() throws Exception {
        crypto = CryptoFactory.getInstance();
    }

    /**
     * Test using a UsernameToken derived key for signing a SOAP body
     */
    @org.junit.Test
    public void testSignature() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setUserInfo("bob", "security");
        builder.addDerivedKey(true, null, 1000);
        builder.prepare(doc);
        
        WSSecSignature sign = new WSSecSignature();
        sign.setCustomTokenValueType(WSConstants.USERNAMETOKEN_NS + "#UsernameToken");
        sign.setCustomTokenId(builder.getId());
        sign.setSecretKey(builder.getDerivedKey());
        sign.setKeyIdentifierType(WSConstants.CUSTOM_SYMM_SIGNING);
        sign.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
        
        Document signedDoc = sign.build(doc, null, secHeader);
        builder.prependToHeader(secHeader);
        
        String outputString = 
            XMLUtils.PrettyDocumentToString(signedDoc);
        assertTrue(outputString.contains("wsse:Username"));
        assertFalse(outputString.contains("wsse:Password"));
        assertTrue(outputString.contains("wsse11:Salt"));
        assertTrue(outputString.contains("wsse11:Iteration"));
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(signedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.UT_SIGN);
        java.security.Principal principal = 
            (java.security.Principal) actionResult.get(WSSecurityEngineResult.TAG_PRINCIPAL);
        assertTrue(principal.getName().contains("bob"));
        
        try {
            verify(signedDoc, false);
            fail("Failure expected on deriving keys from a UsernameToken not allowed");
        } catch (WSSecurityException ex) {
            // expected
        }
    }
    
    
    /**
     * Test using a UsernameToken derived key for signing a SOAP body. In this test the
     * user is "colm" rather than "bob", and so signature verification should fail.
     */
    @org.junit.Test
    public void testBadUserSignature() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setUserInfo("colm", "security");
        builder.addDerivedKey(true, null, 1000);
        builder.prepare(doc);
        
        WSSecSignature sign = new WSSecSignature();
        sign.setCustomTokenValueType(WSConstants.USERNAMETOKEN_NS + "#UsernameToken");
        sign.setCustomTokenId(builder.getId());
        sign.setSecretKey(builder.getDerivedKey());
        sign.setKeyIdentifierType(WSConstants.CUSTOM_SYMM_SIGNING);
        sign.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
        
        Document signedDoc = sign.build(doc, null, secHeader);
        builder.prependToHeader(secHeader);
        
        String outputString = 
            XMLUtils.PrettyDocumentToString(signedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }

        try {
            verify(signedDoc);
            fail("Failure expected on a bad derived signature");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
            // expected
        }
    }
    
    /**
     * Test using a UsernameToken derived key for signing a SOAP body via WSHandler
     */
    @org.junit.Test
    public void testHandlerSignature() throws Exception {
        
        final WSSConfig cfg = WSSConfig.getNewInstance();
        RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        java.util.Map<String, Object> messageContext = new java.util.TreeMap<String, Object>();
        messageContext.put(WSHandlerConstants.PW_CALLBACK_REF, callbackHandler);
        reqData.setMsgContext(messageContext);
        reqData.setUsername("bob");
        
        final java.util.List<Integer> actions = new java.util.ArrayList<Integer>();
        actions.add(WSConstants.UT_SIGN);
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        handler.send(
            WSConstants.UT_SIGN, 
            doc, 
            reqData, 
            actions,
            true
        );
        
        String outputString = 
            XMLUtils.PrettyDocumentToString(doc);
        assertTrue(outputString.contains("wsse:Username"));
        assertFalse(outputString.contains("wsse:Password"));
        assertTrue(outputString.contains("wsse11:Salt"));
        assertTrue(outputString.contains("wsse11:Iteration"));
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(doc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.UT_SIGN);
        java.security.Principal principal = 
            (java.security.Principal) actionResult.get(WSSecurityEngineResult.TAG_PRINCIPAL);
        assertTrue(principal.getName().contains("bob"));
    }
    
    /**
     * Test using a UsernameToken derived key for signing a SOAP body via WSHandler
     */
    @org.junit.Test
    public void testHandlerSignatureIterations() throws Exception {
        
        final WSSConfig cfg = WSSConfig.getNewInstance();
        RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        java.util.Map<String, Object> messageContext = new java.util.TreeMap<String, Object>();
        messageContext.put(WSHandlerConstants.PW_CALLBACK_REF, callbackHandler);
        messageContext.put(WSHandlerConstants.DERIVED_KEY_ITERATIONS, "1234");
        reqData.setMsgContext(messageContext);
        reqData.setUsername("bob");
        
        final java.util.List<Integer> actions = new java.util.ArrayList<Integer>();
        actions.add(WSConstants.UT_SIGN);
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        handler.send(
            WSConstants.UT_SIGN, 
            doc, 
            reqData, 
            actions,
            true
        );
        
        String outputString = 
            XMLUtils.PrettyDocumentToString(doc);
        assertTrue(outputString.contains("wsse:Username"));
        assertFalse(outputString.contains("wsse:Password"));
        assertTrue(outputString.contains("wsse11:Salt"));
        assertTrue(outputString.contains("wsse11:Iteration"));
        assertTrue(outputString.contains("1234"));
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(doc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.UT_SIGN);
        java.security.Principal principal = 
            (java.security.Principal) actionResult.get(WSSecurityEngineResult.TAG_PRINCIPAL);
        assertTrue(principal.getName().contains("bob"));
    }
    
    /**
     * Verifies the soap envelope.
     * 
     * @param doc soap envelope
     * @throws java.lang.Exception Thrown when there is a problem in verification
     */
    private List<WSSecurityEngineResult> verify(Document doc) throws Exception {
        return verify(doc, true);
    }
    
    private List<WSSecurityEngineResult> verify(
        Document doc, 
        boolean allowUsernameTokenDerivedKeys
    ) throws Exception {
        WSSecurityEngine secEngine = new WSSecurityEngine();
        WSSConfig config = WSSConfig.getNewInstance();
        config.setAllowUsernameTokenNoPassword(allowUsernameTokenDerivedKeys);
        secEngine.setWssConfig(config);
        return secEngine.processSecurityHeader(doc, null, callbackHandler, crypto);
    }

}
