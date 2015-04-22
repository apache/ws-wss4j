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

package org.apache.wss4j.dom.handler;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.security.auth.callback.CallbackHandler;

import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSSecurityEngine;
import org.apache.wss4j.dom.WSSecurityEngineResult;
import org.apache.wss4j.dom.common.CustomHandler;
import org.apache.wss4j.dom.common.KeystoreCallbackHandler;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.token.SignatureConfirmation;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.apache.xml.security.utils.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * A set of test-cases for SignatureConfirmation.
 */
public class SignatureConfirmationTest extends org.junit.Assert {
    private static final org.slf4j.Logger LOG = 
        org.slf4j.LoggerFactory.getLogger(SignatureConfirmationTest.class);
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private CallbackHandler callbackHandler = new KeystoreCallbackHandler();
    private Crypto crypto = null;
    
    @org.junit.AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }
    
    public SignatureConfirmationTest() throws Exception {
        crypto = CryptoFactory.getInstance();
    }

    /**
     * Test to see that a signature is saved correctly on the outbound request.
     */
    @SuppressWarnings("unchecked")
    @org.junit.Test
    public void
    testRequestSavedSignature() throws Exception {
        final RequestData reqData = new RequestData();
        java.util.Map<String, Object> msgContext = new java.util.TreeMap<String, Object>();
        msgContext.put(WSHandlerConstants.ENABLE_SIGNATURE_CONFIRMATION, "true");
        msgContext.put(WSHandlerConstants.SIG_PROP_FILE, "crypto.properties");
        msgContext.put("password", "security");
        reqData.setMsgContext(msgContext);
        reqData.setUsername("16c73ab6-b892-458f-abf5-2f875f74882e");
        
        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        HandlerAction action = new HandlerAction(WSConstants.SIGN);
        handler.send(
            doc, 
            reqData, 
            Collections.singletonList(action),
            true
        );
        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString = 
                XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        msgContext = (java.util.Map<String, Object>)reqData.getMsgContext();
        List<byte[]> savedSignatures = 
            (List<byte[]>)msgContext.get(WSHandlerConstants.SEND_SIGV);
        assertTrue(savedSignatures != null && savedSignatures.size() == 1);
        byte[] signatureValue = savedSignatures.get(0);
        assertTrue(signatureValue != null && signatureValue.length > 0);
    }
    
    
    /**
     * Test to see that a signature is not saved on the outbound request if
     * enable signature confirmation is false.
     */
    @SuppressWarnings("unchecked")
    @org.junit.Test
    public void
    testRequestNotSavedSignature() throws Exception {
        final RequestData reqData = new RequestData();
        java.util.Map<String, Object> msgContext = new java.util.TreeMap<String, Object>();
        msgContext.put(WSHandlerConstants.ENABLE_SIGNATURE_CONFIRMATION, "false");
        msgContext.put(WSHandlerConstants.SIG_PROP_FILE, "crypto.properties");
        msgContext.put("password", "security");
        reqData.setMsgContext(msgContext);
        reqData.setUsername("16c73ab6-b892-458f-abf5-2f875f74882e");
        
        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        HandlerAction action = new HandlerAction(WSConstants.SIGN);
        handler.send(
            doc, 
            reqData, 
            Collections.singletonList(action),
            true
        );
        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString = 
                XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        msgContext = (java.util.Map<String, Object>)reqData.getMsgContext();
        List<byte[]> savedSignatures = 
            (List<byte[]>)msgContext.get(WSHandlerConstants.SEND_SIGV);
        assertTrue(savedSignatures == null);
    }
    
    
    /**
     * Test to see that a signature confirmation response is correctly sent on receiving
     * a signed message.
     */
    @SuppressWarnings("unchecked")
    @org.junit.Test
    public void
    testSignatureConfirmationResponse() throws Exception {
        final RequestData reqData = new RequestData();
        java.util.Map<String, Object> msgContext = new java.util.TreeMap<String, Object>();
        msgContext.put(WSHandlerConstants.ENABLE_SIGNATURE_CONFIRMATION, "true");
        msgContext.put(WSHandlerConstants.SIG_PROP_FILE, "crypto.properties");
        msgContext.put("password", "security");
        reqData.setMsgContext(msgContext);
        reqData.setUsername("16c73ab6-b892-458f-abf5-2f875f74882e");
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        HandlerAction action = new HandlerAction(WSConstants.SIGN);
        handler.send(
            doc, 
            reqData, 
            Collections.singletonList(action),
            true
        );
        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString = 
                XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        msgContext = (java.util.Map<String, Object>)reqData.getMsgContext();
        List<byte[]> savedSignatures = 
            (List<byte[]>)msgContext.get(WSHandlerConstants.SEND_SIGV);
        assertTrue(savedSignatures != null && savedSignatures.size() == 1);
        byte[] signatureValue = savedSignatures.get(0);
        assertTrue(signatureValue != null && signatureValue.length > 0);
        
        //
        // Verify the inbound request, and create a response with a Signature Confirmation
        //
        List<WSSecurityEngineResult> results = verify(doc);
        doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        msgContext = (java.util.Map<String, Object>)reqData.getMsgContext();
        WSHandlerResult handlerResult = new WSHandlerResult(null, results);
        List<WSHandlerResult> receivedResults = new ArrayList<WSHandlerResult>();
        receivedResults.add(handlerResult);
        msgContext.put(WSHandlerConstants.RECV_RESULTS, receivedResults);
        action = new HandlerAction(WSConstants.NO_SECURITY);
        handler.send(
            doc, 
            reqData, 
            Collections.singletonList(action),
            false
        );
        String outputString = 
            XMLUtils.PrettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signature Confirmation response....");
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains("SignatureConfirmation"));
        assertTrue(outputString.contains(Base64.encode(signatureValue)));
    }
    
    
    /**
     * Test to see that a signature confirmation response is correctly processed.
     */
    @SuppressWarnings("unchecked")
    @org.junit.Test
    public void
    testSignatureConfirmationProcessing() throws Exception {
        final RequestData reqData = new RequestData();
        java.util.Map<String, Object> msgContext = new java.util.TreeMap<String, Object>();
        msgContext.put(WSHandlerConstants.ENABLE_SIGNATURE_CONFIRMATION, "true");
        msgContext.put(WSHandlerConstants.SIG_PROP_FILE, "crypto.properties");
        msgContext.put("password", "security");
        reqData.setMsgContext(msgContext);
        reqData.setUsername("16c73ab6-b892-458f-abf5-2f875f74882e");
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        HandlerAction action = new HandlerAction(WSConstants.SIGN);
        handler.send(
            doc, 
            reqData, 
            Collections.singletonList(action),
            true
        );
        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString = 
                XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        //
        // Verify the inbound request, and create a response with a Signature Confirmation
        //
        List<WSSecurityEngineResult> results = verify(doc);
        doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        msgContext = (java.util.Map<String, Object>)reqData.getMsgContext();
        WSHandlerResult handlerResult = new WSHandlerResult(null, results);
        List<WSHandlerResult> receivedResults = new ArrayList<WSHandlerResult>();
        receivedResults.add(handlerResult);
        msgContext.put(WSHandlerConstants.RECV_RESULTS, receivedResults);
        handler.send(
            doc, 
            reqData, 
            Collections.singletonList(action),
            false
        );
        String outputString = 
            XMLUtils.PrettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signature Confirmation response....");
            LOG.debug(outputString);
        }
        
        //
        // Verify the SignatureConfirmation response
        //
        results = verify(doc);
        WSSecurityEngineResult scResult = 
            WSSecurityUtil.fetchActionResult(results, WSConstants.SC);
        assertTrue(scResult != null);
        assertTrue(scResult.get(WSSecurityEngineResult.TAG_SIGNATURE_CONFIRMATION) != null);
        handler.signatureConfirmation(reqData, results);
    }
    
    
    /**
     * Test to see that a signature confirmation response that does not contain a wsu:Id fails
     * the BSP compliance is enabled.
     */
    @org.junit.Test
    public void
    testWsuId() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        byte[] randomBytes = WSSecurityUtil.generateNonce(20);
        SignatureConfirmation sigConf = new SignatureConfirmation(doc, randomBytes);
        Element sigConfElement = sigConf.getElement();
        secHeader.getSecurityHeader().appendChild(sigConfElement);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        
        // Verify the results
        WSSecurityEngine newEngine = new WSSecurityEngine();
        try {
            newEngine.processSecurityHeader(doc, null, callbackHandler, crypto);
            fail("Failure expected on a request with no wsu:Id");
        } catch (WSSecurityException ex) {
            // expected
        }
        
        RequestData data = new RequestData();
        data.setCallbackHandler(callbackHandler);
        data.setSigVerCrypto(crypto);
        data.setIgnoredBSPRules(Collections.singletonList(BSPRule.R5441));
        newEngine.processSecurityHeader(doc, "", data);
    }
    
    
    /**
     * Verifies the soap envelope
     * <p/>
     * 
     * @param doc 
     * @throws Exception Thrown when there is a problem in verification
     */
    private List<WSSecurityEngineResult> verify(Document doc) throws Exception {
        List<WSSecurityEngineResult> results = 
            secEngine.processSecurityHeader(doc, null, callbackHandler, crypto);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Verfied and decrypted message:");
            String outputString = 
                XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        return results;
    }
    
}
