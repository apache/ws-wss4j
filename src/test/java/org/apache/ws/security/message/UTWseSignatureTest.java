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

import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.common.CustomHandler;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.common.UsernamePasswordCallbackHandler;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.handler.WSHandlerConstants;

import org.w3c.dom.Document;

import javax.security.auth.callback.CallbackHandler;


/**
 * This a test for deriving a key from a Username Token using a non-standard (WSE) implementation.
 * 
 * @author Werner Dittmann (Wern.erDittmann@siemens.com)
 */
public class UTWseSignatureTest extends org.junit.Assert {
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(UTWseSignatureTest.class);
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private CallbackHandler callbackHandler = new UsernamePasswordCallbackHandler();

    /**
     * Test the specific signing method that use UsernameToken values
     * <p/>
     * 
     * @throws java.lang.Exception Thrown when there is any problem in signing or verification
     */
    @org.junit.Test
    public void testUsernameTokenSigning() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setPasswordType(WSConstants.PASSWORD_TEXT);
        builder.setUserInfo("wernerd", "verySecret");
        builder.addCreated();
        builder.addNonce();
        builder.prepare(doc);
        
        WSSecSignature sign = new WSSecSignature();
        sign.setCustomTokenValueType(WSConstants.USERNAMETOKEN_NS + "#UsernameToken");
        sign.setCustomTokenId(builder.getId());
        sign.setSecretKey(builder.getSecretKey());
        sign.setKeyIdentifierType(WSConstants.CUSTOM_SYMM_SIGNING);
        sign.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
        
        LOG.info("Before signing with UT text....");
        sign.build(doc, null, secHeader);
        LOG.info("Before adding UsernameToken PW Text....");
        builder.prependToHeader(secHeader);
        Document signedDoc = doc;
        if (LOG.isDebugEnabled()) {
            LOG.debug("Message with UserNameToken PW Text:");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        LOG.info("After adding UsernameToken PW Text....");
        verify(signedDoc);
    }
    
    /**
     * Test the specific signing method that use UsernameToken values
     * Test that uses a 32 byte key length for the secret key, instead of the default 16 bytes.
     */
    @org.junit.Test
    public void testWSS226() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setPasswordType(WSConstants.PASSWORD_TEXT);
        builder.setUserInfo("wernerd", "verySecret");
        builder.addCreated();
        builder.setSecretKeyLength(32);
        builder.addNonce();
        builder.prepare(doc);
        
        WSSecSignature sign = new WSSecSignature();
        sign.setCustomTokenValueType(WSConstants.USERNAMETOKEN_NS + "#UsernameToken");
        sign.setCustomTokenId(builder.getId());
        sign.setSecretKey(builder.getSecretKey());
        sign.setKeyIdentifierType(WSConstants.CUSTOM_SYMM_SIGNING);
        sign.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
        
        LOG.info("Before signing with UT text....");
        sign.build(doc, null, secHeader);
        LOG.info("Before adding UsernameToken PW Text....");
        builder.prependToHeader(secHeader);
        Document signedDoc = doc;
        if (LOG.isDebugEnabled()) {
            LOG.debug("Message using a 32 byte key length:");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        //
        // It should fail on the default key length of 16...
        //
        try {
            secEngine.processSecurityHeader(doc, null, callbackHandler, null);
            fail("An error was expected on verifying the signature");
        } catch (Exception ex) {
            // expected
        }
        
        WSSecurityEngine wss226SecurityEngine = new WSSecurityEngine();
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        wssConfig.setSecretKeyLength(32);
        wss226SecurityEngine.setWssConfig(wssConfig);
        wss226SecurityEngine.processSecurityHeader(doc, null, callbackHandler, null);
    }
    
    /**
     * Test that uses a 32 byte key length for the secret key, instead of the default 16 bytes.
     * This test configures the key length via WSHandler.
     */
    @org.junit.Test
    public void testWSS226Handler() throws Exception {
        CustomHandler handler = new CustomHandler();
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        
        RequestData reqData = new RequestData();
        reqData.setWssConfig(WSSConfig.getNewInstance());
        java.util.Map<String, Object> config = new java.util.TreeMap<String, Object>();
        config.put("password", "verySecret");
        config.put(WSHandlerConstants.PASSWORD_TYPE, WSConstants.PW_TEXT);
        config.put(WSHandlerConstants.WSE_SECRET_KEY_LENGTH, "32");
        config.put(WSHandlerConstants.USE_DERIVED_KEY, "false");
        reqData.setUsername("wernerd");
        reqData.setMsgContext(config);
        
        java.util.List<Integer> actions = new java.util.ArrayList<Integer>();
        actions.add(Integer.valueOf(WSConstants.UT_SIGN));
        
        handler.send(WSConstants.UT_SIGN, doc, reqData, actions, true);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Username Token Signature via WSHandler");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        
        //
        // It should fail on the default key length of 16...
        //
        try {
            secEngine.processSecurityHeader(doc, null, callbackHandler, null);
            fail("An error was expected on verifying the signature");
        } catch (Exception ex) {
            // expected
        }
        
        handler.receive(WSConstants.UT_SIGN, reqData);
        
        WSSecurityEngine wss226SecurityEngine = new WSSecurityEngine();
        wss226SecurityEngine.setWssConfig(reqData.getWssConfig());
        wss226SecurityEngine.processSecurityHeader(doc, null, callbackHandler, null);
    }
    
    /**
     * Test the specific signing method that use UsernameToken values
     * <p/>
     * 
     * @throws java.lang.Exception Thrown when there is any problem in signing or verification
     */
    @org.junit.Test
    public void testUsernameTokenSigningDigest() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setPasswordType(WSConstants.PASSWORD_DIGEST);
        builder.setUserInfo("wernerd", "verySecret");
        builder.addCreated();
        builder.addNonce();
        builder.prepare(doc);
        
        WSSecSignature sign = new WSSecSignature();
        sign.setCustomTokenValueType(WSConstants.USERNAMETOKEN_NS + "#UsernameToken");
        sign.setCustomTokenId(builder.getId());
        sign.setSecretKey(builder.getSecretKey());
        sign.setKeyIdentifierType(WSConstants.CUSTOM_SYMM_SIGNING);
        sign.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
        
        LOG.info("Before signing with UT digest....");
        sign.build(doc, null, secHeader);
        LOG.info("Before adding UsernameToken PW Digest....");
        builder.prependToHeader(secHeader);
        Document signedDoc = doc;
        if (LOG.isDebugEnabled()) {
            LOG.debug("Message with UserNameToken PW Digest:");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        LOG.info("After adding UsernameToken PW Digest....");
        verify(signedDoc);
    }

    /**
     * Verifies the soap envelope
     * <p/>
     * 
     * @param env soap envelope
     * @throws java.lang.Exception Thrown when there is a problem in verification
     */
    private void verify(Document doc) throws Exception {
        LOG.info("Before verifying UsernameToken....");
        secEngine.processSecurityHeader(doc, null, callbackHandler, null);
        LOG.info("After verifying UsernameToken....");
    }

}
