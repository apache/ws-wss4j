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

import java.io.IOException;
import java.util.List;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.common.CustomHandler;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.w3c.dom.Document;


/**
 * This is a test for WSS-194 - "Support overriding KeyStore alias for signature so that it can
 * be different than user name used for UsernameToken".
 */
public class SignatureUTAliasTest extends org.junit.Assert implements CallbackHandler {
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(SignatureUTAliasTest.class);
    private WSSecurityEngine secEngine = new WSSecurityEngine();

    /**
     * Test involving adding a Username Token to a SOAP message and signing it, where the
     * private key for signature is extracted from the KeyStore using a different username/alias
     * to the UsernameToken. 
     */
    @org.junit.Test
    public void 
    testUsernameTokenSignatureHandler() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        reqData.setUsername("alice");
        reqData.setPwType(WSConstants.PASSWORD_TEXT);
        java.util.Map<String, Object> messageContext = new java.util.TreeMap<String, Object>();
        messageContext.put(
            WSHandlerConstants.PW_CALLBACK_REF, 
            this
        );
        messageContext.put(WSHandlerConstants.SIGNATURE_USER, "wss40");
        messageContext.put(WSHandlerConstants.SIG_PROP_FILE, "wss40.properties");
        messageContext.put(
            WSHandlerConstants.SIGNATURE_PARTS, 
            "{}{" + WSConstants.WSSE_NS + "}" + "UsernameToken"
        );
        messageContext.put(WSHandlerConstants.SIG_KEY_ID, "DirectReference");
        reqData.setMsgContext(messageContext);
        
        final java.util.List<Integer> actions = new java.util.ArrayList<Integer>();
        actions.add(Integer.valueOf(WSConstants.UT));
        actions.add(Integer.valueOf(WSConstants.SIGN));
        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        handler.send(
            WSConstants.UT | WSConstants.SIGN, 
            doc, 
            reqData, 
            actions,
            true
        );
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        
        verify(doc);
        
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
            secEngine.processSecurityHeader(
                doc, null, this, CryptoFactory.getInstance("wss40CA.properties")
            );
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
                if (pc.getUsage() == WSPasswordCallback.USERNAME_TOKEN
                        && "alice".equals(pc.getIdentifier())) {
                    pc.setPassword("verySecret");
                } else if (pc.getUsage() == WSPasswordCallback.SIGNATURE
                        && "wss40".equals(pc.getIdentifier())) {
                    pc.setPassword("security");
                } else {
                    throw new IOException("Authentication failed");
                }
            } else {
                throw new UnsupportedCallbackException(callbacks[i], "Unrecognized Callback");
            }
        }
    }

    
}
