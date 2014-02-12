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

package org.apache.ws.security.saml;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.security.auth.callback.CallbackHandler;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.common.CustomHandler;
import org.apache.ws.security.common.CustomSamlAssertionValidator;
import org.apache.ws.security.common.KeystoreCallbackHandler;
import org.apache.ws.security.common.SAML1CallbackHandler;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.util.XMLUtils;
import org.w3c.dom.Document;

/**
 * Test-case for sending SAML Assertions using the "action" approach.
 */
public class SamlTokenActionTest extends org.junit.Assert {
    private static final org.slf4j.Logger LOG = 
        org.slf4j.LoggerFactory.getLogger(SamlTokenActionTest.class);
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private Crypto crypto = null;
    
    public SamlTokenActionTest() throws WSSecurityException {
        WSSConfig config = WSSConfig.getNewInstance();
        crypto = CryptoFactory.getInstance("crypto.properties");
        config.setValidator(WSSecurityEngine.SAML_TOKEN, new CustomSamlAssertionValidator());
        config.setValidator(WSSecurityEngine.SAML2_TOKEN, new CustomSamlAssertionValidator());
        secEngine.setWssConfig(config);
    }
    
    @org.junit.Test
    public void testAssertionAction() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        reqData.setUsername("16c73ab6-b892-458f-abf5-2f875f74882e");
        
        CallbackHandler callbackHandler = new KeystoreCallbackHandler();
        
        SAML1CallbackHandler samlCallbackHandler = new SAML1CallbackHandler();
        samlCallbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        samlCallbackHandler.setIssuer("www.example.com");
        
        java.util.Map<String, Object> config = new java.util.TreeMap<String, Object>();
        config.put(WSHandlerConstants.SIG_PROP_FILE, "crypto.properties");
        config.put(WSHandlerConstants.PW_CALLBACK_REF, callbackHandler);
        config.put(WSHandlerConstants.SAML_CALLBACK_REF, samlCallbackHandler);
        config.put(WSHandlerConstants.SAML_PROP_FILE, "saml_sv.properties");
        reqData.setMsgContext(config);
        
        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        handler.send(
            WSConstants.ST_UNSIGNED,
            doc, 
            reqData, 
            Collections.singletonList(WSConstants.ST_UNSIGNED),
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
        
        java.util.Map<String, Object> config = new java.util.TreeMap<String, Object>();
        config.put(WSHandlerConstants.PW_CALLBACK_REF, callbackHandler);
        config.put(WSHandlerConstants.SAML_CALLBACK_REF, samlCallbackHandler);
        config.put(WSHandlerConstants.SAML_PROP_FILE, "saml_hok.properties");
        reqData.setMsgContext(config);
        
        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        handler.send(
            WSConstants.ST_SIGNED,
            doc, 
            reqData, 
            Collections.singletonList(WSConstants.ST_SIGNED),
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
        reqData.setUsername("16c73ab6-b892-458f-abf5-2f875f74882e");
        
        CallbackHandler callbackHandler = new KeystoreCallbackHandler();
        
        SAML1CallbackHandler samlCallbackHandler = new SAML1CallbackHandler();
        samlCallbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        samlCallbackHandler.setIssuer("www.example.com");
        
        java.util.Map<String, Object> config = new java.util.TreeMap<String, Object>();
        config.put(WSHandlerConstants.SIG_PROP_FILE, "crypto.properties");
        config.put(WSHandlerConstants.PW_CALLBACK_REF, callbackHandler);
        config.put(WSHandlerConstants.SAML_CALLBACK_REF, samlCallbackHandler);
        config.put(WSHandlerConstants.SAML_PROP_FILE, "saml_hok.properties");
        config.put(WSHandlerConstants.SIGNATURE_PARTS, "{}{" + WSConstants.SAML_NS + "}Assertion;");
        reqData.setMsgContext(config);
        
        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        List<Integer> actions = new ArrayList<Integer>();
        actions.add(WSConstants.ST_UNSIGNED);
        actions.add(WSConstants.SIGN);
        handler.send(
            WSConstants.ST_UNSIGNED | WSConstants.SIGN,
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
