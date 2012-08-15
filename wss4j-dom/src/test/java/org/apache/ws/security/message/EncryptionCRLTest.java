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

import javax.security.auth.callback.CallbackHandler;

import org.w3c.dom.Document;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.common.CustomHandler;
import org.apache.ws.security.common.KeystoreCallbackHandler;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.handler.WSHandlerConstants;


/**
 * This is a test for Certificate Revocation List checking before encryption. 
 * 
 * This test reuse the revoked certificate from SignatureCRLTest
 * 
  */
public class EncryptionCRLTest extends org.junit.Assert {
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(EncryptionCRLTest.class);
        
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private CallbackHandler keystoreCallbackHandler = new KeystoreCallbackHandler();
    private Crypto crypto = null;
    
    public EncryptionCRLTest() throws Exception {
        crypto = CryptoFactory.getInstance("wss40All.properties");
    }
    
    /**
     * Setup method
     * 
     * @throws java.lang.Exception Thrown when there is a problem in setup
     */
    @org.junit.Before
    public void setUp() throws Exception {
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        wssConfig.setWsiBSPCompliant(true);
        secEngine.setWssConfig(wssConfig);
    }
    
    /**
     * Test that encrypts without certificate revocation check
     * so it should pass
     * 
     * @throws java.lang.Exception Thrown when there is any problem in encryption or decryption
     */
    @org.junit.Test
    public void testEncryptionWithOutRevocationCheck() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        reqData.setEncUser("wss40rev");
        reqData.setEncKeyId(WSConstants.BST_DIRECT_REFERENCE);
        reqData.setEncSymmAlgo(WSConstants.TRIPLE_DES);
        reqData.setEncCrypto(crypto);
        java.util.Map<String, Object> messageContext = new java.util.TreeMap<String, Object>();
        messageContext.put(WSHandlerConstants.PW_CALLBACK_REF, keystoreCallbackHandler);
        reqData.setMsgContext(messageContext);
        reqData.setUsername("wss40rev");
        
        final java.util.List<Integer> actions = new java.util.ArrayList<Integer>();
        actions.add(Integer.valueOf(WSConstants.ENCR));
        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        handler.send(
            WSConstants.ENCR, 
            doc, 
            reqData, 
            actions,
            true
        );
        
        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        
        verify(doc, crypto, keystoreCallbackHandler);
    }
    
    /**
     * Test that encrypts with certificate revocation check
     * so it should fail
     * 
     * @throws java.lang.Exception Thrown when there is any problem in encryption or decryption
     */
    @org.junit.Test
    public void testEncryptionWithRevocationCheck() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        reqData.setEncUser("wss40rev");
        reqData.setEncKeyId(WSConstants.BST_DIRECT_REFERENCE);
        reqData.setEncSymmAlgo(WSConstants.TRIPLE_DES);
        reqData.setEncCrypto(crypto);
        java.util.Map<String, Object> messageContext = new java.util.TreeMap<String, Object>();
        messageContext.put(WSHandlerConstants.PW_CALLBACK_REF, keystoreCallbackHandler);
        reqData.setMsgContext(messageContext);
        reqData.setUsername("wss40rev");
        
        final java.util.List<Integer> actions = new java.util.ArrayList<Integer>();
        actions.add(Integer.valueOf(WSConstants.ENCR));
        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        handler.setOption(WSHandlerConstants.ENABLE_REVOCATION, "true");
        try {
            handler.send(
                         WSConstants.ENCR, 
                         doc, 
                         reqData, 
                         actions,
                         true
            );
            fail ("Failure expected on a revoked certificate");
        } catch (Exception ex) {
            String errorMessage = ex.getMessage();
            // Different errors using different JDKs...
            assertTrue(errorMessage.contains("Certificate has been revoked")
                || errorMessage.contains("Certificate revocation")
                || errorMessage.contains("Error during certificate path validation"));
        }
       
    }
    
    /**
     * Verifies the soap envelope <p/>
     * 
     * @param envelope
     * @throws Exception
     *             Thrown when there is a problem in verification
     */
    private void verify(
        Document doc, Crypto decCrypto, CallbackHandler handler
    ) throws Exception {
        secEngine.processSecurityHeader(doc, null, handler, decCrypto);
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
    }
}