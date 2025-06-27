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

import java.util.*;

import javax.security.auth.callback.CallbackHandler;

import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.SOAPUtil;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.common.dom.WSConstants;
import org.apache.wss4j.dom.common.CustomHandler;
import org.apache.wss4j.common.crypto.KeystoreCallbackHandler;

import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.common.dom.RequestData;
import org.apache.wss4j.common.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.common.dom.message.WSSecHeader;
import org.apache.wss4j.common.dom.message.token.SignatureConfirmation;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * A set of test-cases for SignatureConfirmation.
 */
public class SignatureConfirmationTest {
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(SignatureConfirmationTest.class);
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private CallbackHandler callbackHandler = new KeystoreCallbackHandler();
    private Crypto crypto;

    public SignatureConfirmationTest() throws Exception {
        crypto = CryptoFactory.getInstance();
    }

    /**
     * Test to see that a signature is saved correctly on the outbound request.
     */
    @SuppressWarnings("unchecked")
    @Test
    public void
    testRequestSavedSignature() throws Exception {
        final RequestData reqData = new RequestData();
        java.util.Map<String, Object> msgContext = new java.util.TreeMap<>();
        msgContext.put(WSHandlerConstants.ENABLE_SIGNATURE_CONFIRMATION, "true");
        msgContext.put(WSHandlerConstants.SIG_PROP_FILE, "crypto.properties");
        msgContext.put(WSHandlerConstants.PW_CALLBACK_REF, callbackHandler);
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
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        msgContext = (java.util.Map<String, Object>)reqData.getMsgContext();
        Set<Integer> savedSignatures =
            (Set<Integer>)msgContext.get(WSHandlerConstants.SEND_SIGV);
        assertTrue(savedSignatures != null && savedSignatures.size() == 1);
        Integer signatureValue = savedSignatures.iterator().next();
        assertTrue(signatureValue != null && signatureValue != 0);
    }


    /**
     * Test to see that a signature is not saved on the outbound request if
     * enable signature confirmation is false.
     */
    @SuppressWarnings("unchecked")
    @Test
    public void
    testRequestNotSavedSignature() throws Exception {
        final RequestData reqData = new RequestData();
        java.util.Map<String, Object> msgContext = new java.util.TreeMap<>();
        msgContext.put(WSHandlerConstants.ENABLE_SIGNATURE_CONFIRMATION, "false");
        msgContext.put(WSHandlerConstants.SIG_PROP_FILE, "crypto.properties");
        msgContext.put(WSHandlerConstants.PW_CALLBACK_REF, callbackHandler);
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
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        msgContext = (java.util.Map<String, Object>)reqData.getMsgContext();
        Set<Integer> savedSignatures =
            (Set<Integer>)msgContext.get(WSHandlerConstants.SEND_SIGV);
        assertNull(savedSignatures);
    }


    /**
     * Test to see that a signature confirmation response is correctly sent on receiving
     * a signed message.
     */
    @SuppressWarnings("unchecked")
    @Test
    public void
    testSignatureConfirmationResponse() throws Exception {
        final RequestData reqData = new RequestData();
        java.util.Map<String, Object> msgContext = new java.util.TreeMap<>();
        msgContext.put(WSHandlerConstants.ENABLE_SIGNATURE_CONFIRMATION, "true");
        msgContext.put(WSHandlerConstants.SIG_PROP_FILE, "crypto.properties");
        msgContext.put(WSHandlerConstants.PW_CALLBACK_REF, callbackHandler);
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
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        msgContext = (java.util.Map<String, Object>)reqData.getMsgContext();
        Set<Integer> savedSignatures =
            (Set<Integer>)msgContext.get(WSHandlerConstants.SEND_SIGV);
        assertTrue(savedSignatures != null && savedSignatures.size() == 1);
        Integer signatureValue = savedSignatures.iterator().next();
        assertTrue(signatureValue != null && signatureValue != 0);

        //
        // Verify the inbound request, and create a response with a Signature Confirmation
        //
        WSHandlerResult results = verify(doc);
        doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        msgContext = (java.util.Map<String, Object>)reqData.getMsgContext();
        List<WSHandlerResult> receivedResults = new ArrayList<>();
        receivedResults.add(results);
        msgContext.put(WSHandlerConstants.RECV_RESULTS, receivedResults);
        action = new HandlerAction(WSConstants.NO_SECURITY);
        handler.send(
            doc,
            reqData,
            Collections.singletonList(action),
            false
        );
        String outputString =
            XMLUtils.prettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signature Confirmation response....");
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains("SignatureConfirmation"));
        assertTrue(outputString.contains("Value"));
    }


    /**
     * Test to see that a signature confirmation response is correctly processed.
     */
    @SuppressWarnings("unchecked")
    @Test
    public void
    testSignatureConfirmationProcessing() throws Exception {
        final RequestData reqData = new RequestData();
        java.util.Map<String, Object> msgContext = new java.util.TreeMap<>();
        msgContext.put(WSHandlerConstants.ENABLE_SIGNATURE_CONFIRMATION, "true");
        msgContext.put(WSHandlerConstants.SIG_PROP_FILE, "crypto.properties");
        msgContext.put(WSHandlerConstants.PW_CALLBACK_REF, callbackHandler);
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
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        //
        // Verify the inbound request, and create a response with a Signature Confirmation
        //
        WSHandlerResult results = verify(doc);
        doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        msgContext = (java.util.Map<String, Object>)reqData.getMsgContext();
        List<WSHandlerResult> receivedResults = new ArrayList<>();
        receivedResults.add(results);
        msgContext.put(WSHandlerConstants.RECV_RESULTS, receivedResults);
        handler.send(
            doc,
            reqData,
            Collections.singletonList(action),
            false
        );
        String outputString =
            XMLUtils.prettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signature Confirmation response....");
            LOG.debug(outputString);
        }

        //
        // Verify the SignatureConfirmation response
        //
        results = verify(doc);
        WSSecurityEngineResult scResult =
            results.getActionResults().get(WSConstants.SC).get(0);
        assertNotNull(scResult);
        assertNotNull(scResult.get(WSSecurityEngineResult.TAG_SIGNATURE_CONFIRMATION));
        handler.signatureConfirmation(reqData, results);
    }


    /**
     * Test to see that a signature confirmation response that does not contain a wsu:Id fails
     * the BSP compliance is enabled.
     */
    @Test
    public void testWsuId() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        Random random = new Random();
        byte[] randomBytes = new byte[20];
        random.nextBytes(randomBytes);
        SignatureConfirmation sigConf = new SignatureConfirmation(doc, randomBytes);
        Element sigConfElement = sigConf.getElement();
        secHeader.getSecurityHeaderElement().appendChild(sigConfElement);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        // Verify the results
        WSSecurityEngine newEngine = new WSSecurityEngine();
        try {
            newEngine.processSecurityHeader(doc, null, callbackHandler, crypto);
            fail("Failure expected on a request with no wsu:Id");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY);
        }

        RequestData data = new RequestData();
        data.setCallbackHandler(callbackHandler);
        data.setSigVerCrypto(crypto);
        data.setIgnoredBSPRules(Collections.singletonList(BSPRule.R5441));
        newEngine.processSecurityHeader(doc, data);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testSignatureResponseForUnsignedRequest() throws Exception {
        final RequestData reqData = new RequestData();
        java.util.Map<String, Object> msgContext = new java.util.TreeMap<>();
        msgContext.put(WSHandlerConstants.ENABLE_SIGNATURE_CONFIRMATION, "true");
        msgContext.put(WSHandlerConstants.SIG_PROP_FILE, "crypto.properties");
        msgContext.put(WSHandlerConstants.PW_CALLBACK_REF, callbackHandler);
        reqData.setMsgContext(msgContext);
        reqData.setUsername("16c73ab6-b892-458f-abf5-2f875f74882e");

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        HandlerAction action = new HandlerAction(WSConstants.NO_SECURITY);
        handler.send(
            doc,
            reqData,
            Collections.singletonList(action),
            true
        );
        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString =
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        //
        // Verify the inbound request, and create a response with a Signature Confirmation
        //
        WSHandlerResult results = verify(doc);
        doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        msgContext = (java.util.Map<String, Object>)reqData.getMsgContext();
        List<WSHandlerResult> receivedResults = new ArrayList<>();
        receivedResults.add(results);
        msgContext.put(WSHandlerConstants.RECV_RESULTS, receivedResults);
        action = new HandlerAction(WSConstants.NO_SECURITY);
        handler.send(
            doc,
            reqData,
            Collections.singletonList(action),
            false
        );
        String outputString =
            XMLUtils.prettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signature Confirmation response....");
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains("SignatureConfirmation"));
        // We should have no Value attribute
        assertFalse(outputString.contains("Value"));
    }

    /**
     * Verifies the soap envelope
     * <p/>
     *
     * @param doc
     * @throws Exception Thrown when there is a problem in verification
     */
    private WSHandlerResult verify(Document doc) throws Exception {
        WSHandlerResult results =
            secEngine.processSecurityHeader(doc, null, callbackHandler, crypto);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Verfied and decrypted message:");
            String outputString =
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        return results;
    }

}