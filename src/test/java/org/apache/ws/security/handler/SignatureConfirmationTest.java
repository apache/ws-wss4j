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

package org.apache.ws.security.handler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.common.CustomHandler;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.handler.WSHandlerResult;
import org.apache.ws.security.util.Base64;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;

import java.io.IOException;
import java.util.List;
import java.util.ArrayList;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;


/**
 * A set of test-cases for SignatureConfirmation.
 */
public class SignatureConfirmationTest extends org.junit.Assert implements CallbackHandler {
    private static final Log LOG = LogFactory.getLog(SignatureConfirmationTest.class);
    private static final String SOAPMSG = 
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" 
        + "<SOAP-ENV:Envelope "
        +   "xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" "
        +   "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" "
        +   "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" 
        +   "<SOAP-ENV:Body>" 
        +       "<add xmlns=\"http://ws.apache.org/counter/counter_port_type\">" 
        +           "<value xmlns=\"\">15</value>" 
        +       "</add>" 
        +   "</SOAP-ENV:Body>" 
        + "</SOAP-ENV:Envelope>";

    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private Crypto crypto = CryptoFactory.getInstance();

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
        
        final java.util.List<Integer> actions = new java.util.ArrayList<Integer>();
        actions.add(new Integer(WSConstants.SIGN));
        final Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        CustomHandler handler = new CustomHandler();
        handler.send(
            WSConstants.SIGN, doc, reqData, actions, true
        );
        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        msgContext = (java.util.Map<String, Object>)reqData.getMsgContext();
        List<byte[]> savedSignatures = 
            (List<byte[]>)msgContext.get(WSHandlerConstants.SEND_SIGV);
        assertTrue(savedSignatures != null && savedSignatures.size() == 1);
        byte[] signatureValue = (byte[])savedSignatures.get(0);
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
        
        final java.util.List<Integer> actions = new java.util.ArrayList<Integer>();
        actions.add(new Integer(WSConstants.SIGN));
        final Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        CustomHandler handler = new CustomHandler();
        handler.send(
            WSConstants.SIGN, doc, reqData, actions, true
        );
        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
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
        
        final java.util.List<Integer> actions = new java.util.ArrayList<Integer>();
        actions.add(new Integer(WSConstants.SIGN));
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        CustomHandler handler = new CustomHandler();
        handler.send(
            WSConstants.SIGN, doc, reqData, actions, true
        );
        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        msgContext = (java.util.Map<String, Object>)reqData.getMsgContext();
        List<byte[]> savedSignatures = 
            (List<byte[]>)msgContext.get(WSHandlerConstants.SEND_SIGV);
        assertTrue(savedSignatures != null && savedSignatures.size() == 1);
        byte[] signatureValue = (byte[])savedSignatures.get(0);
        assertTrue(signatureValue != null && signatureValue.length > 0);
        
        //
        // Verify the inbound request, and create a response with a Signature Confirmation
        //
        List<WSSecurityEngineResult> results = verify(doc);
        actions.clear();
        doc = SOAPUtil.toSOAPPart(SOAPMSG);
        msgContext = (java.util.Map<String, Object>)reqData.getMsgContext();
        WSHandlerResult handlerResult = new WSHandlerResult(null, results);
        List<WSHandlerResult> receivedResults = new ArrayList<WSHandlerResult>();
        receivedResults.add(handlerResult);
        msgContext.put(WSHandlerConstants.RECV_RESULTS, receivedResults);
        handler.send(
            WSConstants.NO_SECURITY, doc, reqData, actions, false
        );
        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signature Confirmation response....");
            LOG.debug(outputString);
        }
        assertTrue(outputString.indexOf("SignatureConfirmation") != -1);
        assertTrue(outputString.indexOf(Base64.encode(signatureValue)) != -1);
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
        
        final java.util.List<Integer> actions = new java.util.ArrayList<Integer>();
        actions.add(new Integer(WSConstants.SIGN));
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        CustomHandler handler = new CustomHandler();
        handler.send(
            WSConstants.SIGN, doc, reqData, actions, true
        );
        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        //
        // Verify the inbound request, and create a response with a Signature Confirmation
        //
        List<WSSecurityEngineResult> results = verify(doc);
        actions.clear();
        doc = SOAPUtil.toSOAPPart(SOAPMSG);
        msgContext = (java.util.Map<String, Object>)reqData.getMsgContext();
        WSHandlerResult handlerResult = new WSHandlerResult(null, results);
        List<WSHandlerResult> receivedResults = new ArrayList<WSHandlerResult>();
        receivedResults.add(handlerResult);
        msgContext.put(WSHandlerConstants.RECV_RESULTS, receivedResults);
        handler.send(
            WSConstants.NO_SECURITY, doc, reqData, actions, false
        );
        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
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
     * Verifies the soap envelope
     * <p/>
     * 
     * @param doc 
     * @throws Exception Thrown when there is a problem in verification
     */
    private List<WSSecurityEngineResult> verify(Document doc) throws Exception {
        List<WSSecurityEngineResult> results = 
            secEngine.processSecurityHeader(doc, null, this, crypto);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Verfied and decrypted message:");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        return results;
    }
    
    
    public void handle(Callback[] callbacks)
        throws IOException, UnsupportedCallbackException {
        for (int i = 0; i < callbacks.length; i++) {
            if (callbacks[i] instanceof WSPasswordCallback) {
                WSPasswordCallback pc = (WSPasswordCallback) callbacks[i];
                /*
                 * here call a function/method to lookup the password for
                 * the given identifier (e.g. a user name or keystore alias)
                 * e.g.: pc.setPassword(passStore.getPassword(pc.getIdentfifier))
                 * for Testing we supply a fixed name here.
                 */
                pc.setPassword("security");
            } else {
                throw new UnsupportedCallbackException(callbacks[i], "Unrecognized Callback");
            }
        }
}
}
