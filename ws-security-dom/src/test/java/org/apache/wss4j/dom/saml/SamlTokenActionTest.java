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

package org.apache.wss4j.dom.saml;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.security.auth.callback.CallbackHandler;

import org.w3c.dom.Document;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSSConfig;
import org.apache.wss4j.dom.WSSecurityEngine;
import org.apache.wss4j.dom.WSSecurityEngineResult;
import org.apache.wss4j.dom.common.CustomHandler;
import org.apache.wss4j.dom.common.CustomSamlAssertionValidator;
import org.apache.wss4j.dom.common.KeystoreCallbackHandler;
import org.apache.wss4j.dom.common.SAML1CallbackHandler;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.dom.handler.HandlerAction;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerConstants;

/**
 * Test-case for sending SAML Assertions using the "action" approach.
 */
public class SamlTokenActionTest extends org.junit.Assert {
    private static final org.slf4j.Logger LOG = 
        org.slf4j.LoggerFactory.getLogger(SamlTokenActionTest.class);
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private Crypto crypto = null;
    
    @org.junit.AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }

    public SamlTokenActionTest() throws WSSecurityException {
        WSSConfig config = WSSConfig.getNewInstance();
        crypto = CryptoFactory.getInstance("wss40.properties");
        config.setValidator(WSSecurityEngine.SAML_TOKEN, new CustomSamlAssertionValidator());
        config.setValidator(WSSecurityEngine.SAML2_TOKEN, new CustomSamlAssertionValidator());
        config.setValidateSamlSubjectConfirmation(false);
        secEngine.setWssConfig(config);
    }
    
    @org.junit.Test
    public void testAssertionAction() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        reqData.setUsername("wss40");
        
        CallbackHandler callbackHandler = new KeystoreCallbackHandler();
        
        SAML1CallbackHandler samlCallbackHandler = new SAML1CallbackHandler();
        samlCallbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        samlCallbackHandler.setIssuer("www.example.com");
        
        java.util.Map<String, Object> config = new java.util.TreeMap<String, Object>();
        config.put(WSHandlerConstants.SIG_PROP_FILE, "wss40.properties");
        config.put(WSHandlerConstants.PW_CALLBACK_REF, callbackHandler);
        config.put(WSHandlerConstants.SAML_CALLBACK_REF, samlCallbackHandler);
        reqData.setMsgContext(config);
        
        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        HandlerAction action = new HandlerAction(WSConstants.ST_UNSIGNED);
        handler.send(
            doc, 
            reqData, 
            Collections.singletonList(action),
            true
        );
        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        
        verify(doc, callbackHandler);
    }
    
    @org.junit.Test
    public void testSignedAssertionAction() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        
        CallbackHandler callbackHandler = new KeystoreCallbackHandler();
        
        SAML1CallbackHandler samlCallbackHandler = new SAML1CallbackHandler();
        samlCallbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        samlCallbackHandler.setIssuer("www.example.com");
        samlCallbackHandler.setIssuerCrypto(crypto);
        samlCallbackHandler.setIssuerName("wss40");
        samlCallbackHandler.setIssuerPassword("security");
        
        java.util.Map<String, Object> config = new java.util.TreeMap<String, Object>();
        config.put(WSHandlerConstants.PW_CALLBACK_REF, callbackHandler);
        config.put(WSHandlerConstants.SAML_CALLBACK_REF, samlCallbackHandler);
        reqData.setMsgContext(config);
        
        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        HandlerAction action = new HandlerAction(WSConstants.ST_SIGNED);
        handler.send(
            doc, 
            reqData, 
            Collections.singletonList(action),
            true
        );
        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        
        verify(doc, callbackHandler);
    }
    
    @org.junit.Test
    public void testAssertionWithSignatureAction() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        reqData.setUsername("wss40");
        
        CallbackHandler callbackHandler = new KeystoreCallbackHandler();
        
        SAML1CallbackHandler samlCallbackHandler = new SAML1CallbackHandler();
        samlCallbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        samlCallbackHandler.setIssuer("www.example.com");
        
        java.util.Map<String, Object> config = new java.util.TreeMap<String, Object>();
        config.put(WSHandlerConstants.SIG_PROP_FILE, "wss40.properties");
        config.put(WSHandlerConstants.PW_CALLBACK_REF, callbackHandler);
        config.put(WSHandlerConstants.SAML_CALLBACK_REF, samlCallbackHandler);
        config.put(WSHandlerConstants.SIGNATURE_PARTS, "{}{" + WSConstants.SAML_NS + "}Assertion;");
        reqData.setMsgContext(config);
        
        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        List<HandlerAction> actions = new ArrayList<>();
        actions.add(new HandlerAction(WSConstants.ST_UNSIGNED));
        actions.add(new HandlerAction(WSConstants.SIGN));
        handler.send(
            doc, 
            reqData, 
            actions,
            true
        );
        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        
        verify(doc, callbackHandler);
    }
    
    private List<WSSecurityEngineResult> verify(
        Document doc, CallbackHandler callbackHandler
    ) throws Exception {
        List<WSSecurityEngineResult> results = 
            secEngine.processSecurityHeader(doc, null, callbackHandler, crypto);
        String outputString = 
            XMLUtils.PrettyDocumentToString(doc);
        assertTrue(outputString.indexOf("counter_port_type") > 0 ? true : false);
        return results;
    }
    
}
