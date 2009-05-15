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

package wssec;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.apache.axis.Message;
import org.apache.axis.MessageContext;
import org.apache.axis.client.AxisClient;
import org.apache.axis.configuration.NullProvider;
import org.apache.axis.message.SOAPEnvelope;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.handler.WSHandler;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.handler.WSHandlerResult;
import org.apache.ws.security.util.Base64;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Vector;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;


/**
 * A set of test-cases for SignatureConfirmation.
 */
public class SignatureConfirmationTest extends TestCase implements CallbackHandler {
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

    private MessageContext msgContext;
    private SOAPEnvelope unsignedEnvelope;
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private Crypto crypto = CryptoFactory.getInstance();

    /**
     * TestWSSecurity constructor
     * 
     * @param name name of the test
     */
    public SignatureConfirmationTest(String name) {
        super(name);
    }

    /**
     * JUnit suite
     * 
     * @return a junit test suite
     */
    public static Test suite() {
        return new TestSuite(SignatureConfirmationTest.class);
    }

    /**
     * Setup method
     * 
     * @throws java.lang.Exception Thrown when there is a problem in setup
     */
    protected void setUp() throws Exception {
        AxisClient tmpEngine = new AxisClient(new NullProvider());
        msgContext = new MessageContext(tmpEngine);
        unsignedEnvelope = getSOAPEnvelope();
    }

    /**
     * Constructs a soap envelope
     * 
     * @return soap envelope
     * @throws java.lang.Exception if there is any problem constructing the soap envelope
     */
    protected SOAPEnvelope getSOAPEnvelope() throws Exception {
        InputStream in = new ByteArrayInputStream(SOAPMSG.getBytes());
        Message msg = new Message(in);
        msg.setMessageContext(msgContext);
        return msg.getSOAPEnvelope();
    }

    
    /**
     * Test to see that a signature is saved correctly on the outbound request.
     */
    public void
    testRequestSavedSignature() throws Exception {
        final RequestData reqData = new RequestData();
        java.util.Map msgContext = new java.util.TreeMap();
        msgContext.put(WSHandlerConstants.ENABLE_SIGNATURE_CONFIRMATION, "true");
        msgContext.put(WSHandlerConstants.SIG_PROP_FILE, "crypto.properties");
        reqData.setMsgContext(msgContext);
        reqData.setUsername("16c73ab6-b892-458f-abf5-2f875f74882e");
        
        final java.util.Vector actions = new java.util.Vector();
        actions.add(new Integer(WSConstants.SIGN));
        final Document doc = unsignedEnvelope.getAsDocument();
        MyHandler handler = new MyHandler();
        handler.doit(
            WSConstants.SIGN, doc, reqData, actions, true
        );
        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        msgContext = (java.util.Map)reqData.getMsgContext();
        List savedSignatures = (List)msgContext.get(WSHandlerConstants.SEND_SIGV);
        assertTrue(savedSignatures != null && savedSignatures.size() == 1);
        byte[] signatureValue = (byte[])savedSignatures.get(0);
        assertTrue(signatureValue != null && signatureValue.length > 0);
    }
    
    
    /**
     * Test to see that a signature is not saved on the outbound request if
     * enable signature confirmation is false.
     */
    public void
    testRequestNotSavedSignature() throws Exception {
        final RequestData reqData = new RequestData();
        java.util.Map msgContext = new java.util.TreeMap();
        msgContext.put(WSHandlerConstants.ENABLE_SIGNATURE_CONFIRMATION, "false");
        msgContext.put(WSHandlerConstants.SIG_PROP_FILE, "crypto.properties");
        reqData.setMsgContext(msgContext);
        reqData.setUsername("16c73ab6-b892-458f-abf5-2f875f74882e");
        
        final java.util.Vector actions = new java.util.Vector();
        actions.add(new Integer(WSConstants.SIGN));
        final Document doc = unsignedEnvelope.getAsDocument();
        MyHandler handler = new MyHandler();
        handler.doit(
            WSConstants.SIGN, doc, reqData, actions, true
        );
        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        msgContext = (java.util.Map)reqData.getMsgContext();
        List savedSignatures = (List)msgContext.get(WSHandlerConstants.SEND_SIGV);
        assertTrue(savedSignatures == null);
    }
    
    
    /**
     * Test to see that a signature confirmation response is correctly sent on receiving
     * a signed message.
     */
    public void
    testSignatureConfirmationResponse() throws Exception {
        final RequestData reqData = new RequestData();
        java.util.Map msgContext = new java.util.TreeMap();
        msgContext.put(WSHandlerConstants.ENABLE_SIGNATURE_CONFIRMATION, "true");
        msgContext.put(WSHandlerConstants.SIG_PROP_FILE, "crypto.properties");
        reqData.setMsgContext(msgContext);
        reqData.setUsername("16c73ab6-b892-458f-abf5-2f875f74882e");
        
        final java.util.Vector actions = new java.util.Vector();
        actions.add(new Integer(WSConstants.SIGN));
        Document doc = unsignedEnvelope.getAsDocument();
        MyHandler handler = new MyHandler();
        handler.doit(
            WSConstants.SIGN, doc, reqData, actions, true
        );
        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        msgContext = (java.util.Map)reqData.getMsgContext();
        List savedSignatures = (List)msgContext.get(WSHandlerConstants.SEND_SIGV);
        assertTrue(savedSignatures != null && savedSignatures.size() == 1);
        byte[] signatureValue = (byte[])savedSignatures.get(0);
        assertTrue(signatureValue != null && signatureValue.length > 0);
        
        //
        // Verify the inbound request, and create a response with a Signature Confirmation
        //
        List results = verify(doc);
        actions.clear();
        doc = unsignedEnvelope.getAsDocument();
        msgContext = (java.util.Map)reqData.getMsgContext();
        WSHandlerResult handlerResult = new WSHandlerResult(null, results);
        List receivedResults = new Vector();
        receivedResults.add(handlerResult);
        msgContext.put(WSHandlerConstants.RECV_RESULTS, receivedResults);
        handler.doit(
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
    public void
    testSignatureConfirmationProcessing() throws Exception {
        final RequestData reqData = new RequestData();
        java.util.Map msgContext = new java.util.TreeMap();
        msgContext.put(WSHandlerConstants.ENABLE_SIGNATURE_CONFIRMATION, "true");
        msgContext.put(WSHandlerConstants.SIG_PROP_FILE, "crypto.properties");
        reqData.setMsgContext(msgContext);
        reqData.setUsername("16c73ab6-b892-458f-abf5-2f875f74882e");
        
        final java.util.Vector actions = new java.util.Vector();
        actions.add(new Integer(WSConstants.SIGN));
        Document doc = unsignedEnvelope.getAsDocument();
        MyHandler handler = new MyHandler();
        handler.doit(
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
        List results = verify(doc);
        actions.clear();
        doc = unsignedEnvelope.getAsDocument();
        msgContext = (java.util.Map)reqData.getMsgContext();
        WSHandlerResult handlerResult = new WSHandlerResult(null, results);
        List receivedResults = new Vector();
        receivedResults.add(handlerResult);
        msgContext.put(WSHandlerConstants.RECV_RESULTS, receivedResults);
        handler.doit(
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
    private Vector verify(Document doc) throws Exception {
        Vector results = secEngine.processSecurityHeader(doc, null, this, crypto);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Verfied and decrypted message:");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        return results;
    }
    
    
    /**
     * a trivial extension of the WSHandler type
     */
    private static class MyHandler extends WSHandler {
        
        public Object 
        getOption(String key) {
            return null;
        }
        
        public void 
        setProperty(
            Object ctx, 
            String key, 
            Object value
        ) {
            ((java.util.Map)ctx).put(key, value);
        }

        public Object 
        getProperty(Object ctx, String key) {
            return ((java.util.Map)ctx).get(key);
        }
    
        public void 
        setPassword(Object msgContext, String password) {
        }
        
        public String 
        getPassword(Object msgContext) {
            return "security";
        }

        void doit(
            int action, 
            Document doc,
            RequestData reqData, 
            java.util.Vector actions,
            boolean request
        ) throws org.apache.ws.security.WSSecurityException {
            doSenderAction(
                action, 
                doc, 
                reqData, 
                actions,
                request
            );
        }
        
        void signatureConfirmation(
            RequestData requestData,
            List results
        ) throws org.apache.ws.security.WSSecurityException {
            checkSignatureConfirmation(requestData, results);
        }
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
