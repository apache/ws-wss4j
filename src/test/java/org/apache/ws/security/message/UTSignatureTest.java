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

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.common.CustomHandler;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.common.UsernamePasswordCallbackHandler;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.util.WSSecurityUtil;
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
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(UTSignatureTest.class);
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private CallbackHandler callbackHandler = new UsernamePasswordCallbackHandler();
    private Crypto crypto = null;
    
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
        sign.setSecretKey(builder.getSecretKey());
        sign.setKeyIdentifierType(WSConstants.CUSTOM_SYMM_SIGNING);
        sign.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
        
        Document signedDoc = sign.build(doc, null, secHeader);
        builder.prependToHeader(secHeader);
        
        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
        assertTrue(outputString.indexOf("wsse:Username") != -1);
        assertTrue(outputString.indexOf("wsse:Password") == -1);
        assertTrue(outputString.indexOf("wsse11:Salt") != -1);
        assertTrue(outputString.indexOf("wsse11:Iteration") != -1);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(signedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.UT_SIGN);
        java.security.Principal principal = 
            (java.security.Principal) actionResult.get(WSSecurityEngineResult.TAG_PRINCIPAL);
        assertTrue(principal.getName().indexOf("bob") != -1);
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
        sign.setSecretKey(builder.getSecretKey());
        sign.setKeyIdentifierType(WSConstants.CUSTOM_SYMM_SIGNING);
        sign.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
        
        Document signedDoc = sign.build(doc, null, secHeader);
        builder.prependToHeader(secHeader);
        
        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }

        try {
            verify(signedDoc);
            fail("Failure expected on a bad derived signature");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.FAILED_AUTHENTICATION);
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
        messageContext.put(WSHandlerConstants.USE_DERIVED_KEY, "true");
        reqData.setMsgContext(messageContext);
        reqData.setUsername("bob");
        
        final java.util.List<Integer> actions = new java.util.ArrayList<Integer>();
        actions.add(Integer.valueOf(WSConstants.UT_SIGN));
        
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
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
        assertTrue(outputString.indexOf("wsse:Username") != -1);
        assertTrue(outputString.indexOf("wsse:Password") == -1);
        assertTrue(outputString.indexOf("wsse11:Salt") != -1);
        assertTrue(outputString.indexOf("wsse11:Iteration") != -1);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(doc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.UT_SIGN);
        java.security.Principal principal = 
            (java.security.Principal) actionResult.get(WSSecurityEngineResult.TAG_PRINCIPAL);
        assertTrue(principal.getName().indexOf("bob") != -1);
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
        messageContext.put(WSHandlerConstants.USE_DERIVED_KEY, "true");
        messageContext.put(WSHandlerConstants.DERIVED_KEY_ITERATIONS, "1234");
        reqData.setMsgContext(messageContext);
        reqData.setUsername("bob");
        
        final java.util.List<Integer> actions = new java.util.ArrayList<Integer>();
        actions.add(Integer.valueOf(WSConstants.UT_SIGN));
        
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
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
        assertTrue(outputString.indexOf("wsse:Username") != -1);
        assertTrue(outputString.indexOf("wsse:Password") == -1);
        assertTrue(outputString.indexOf("wsse11:Salt") != -1);
        assertTrue(outputString.indexOf("wsse11:Iteration") != -1);
        assertTrue(outputString.indexOf("1234") != -1);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(doc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.UT_SIGN);
        java.security.Principal principal = 
            (java.security.Principal) actionResult.get(WSSecurityEngineResult.TAG_PRINCIPAL);
        assertTrue(principal.getName().indexOf("bob") != -1);
    }
    
    /**
     * Verifies the soap envelope.
     * 
     * @param env soap envelope
     * @throws java.lang.Exception Thrown when there is a problem in verification
     */
    private List<WSSecurityEngineResult> verify(Document doc) throws Exception {
        return secEngine.processSecurityHeader(doc, null, callbackHandler, crypto);
    }

}
