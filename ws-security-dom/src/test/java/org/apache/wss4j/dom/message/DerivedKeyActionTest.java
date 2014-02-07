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

package org.apache.wss4j.dom.message;

import java.util.Collections;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.callback.CallbackHandler;

import org.w3c.dom.Document;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.derivedKey.ConversationConstants;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSSConfig;
import org.apache.wss4j.dom.WSSecurityEngine;
import org.apache.wss4j.dom.WSSecurityEngineResult;
import org.apache.wss4j.dom.common.CustomHandler;
import org.apache.wss4j.dom.common.KeystoreCallbackHandler;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.common.SecretKeyCallbackHandler;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.dom.handler.HandlerAction;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.junit.Assert;

/**
 * A set of tests for using a derived key for encryption/signature using WSHandler actions.
 */
public class DerivedKeyActionTest extends org.junit.Assert {
    private static final org.slf4j.Logger LOG = 
        org.slf4j.LoggerFactory.getLogger(DerivedKeyActionTest.class);
    private CallbackHandler callbackHandler = new KeystoreCallbackHandler();
    private Crypto crypto = null;
    
    @org.junit.AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }
    
    public DerivedKeyActionTest() throws Exception {
        crypto = CryptoFactory.getInstance("wss40.properties");
        WSSConfig.init();
    }

    @org.junit.Test
    public void testSignatureThumbprintSHA1() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        reqData.setUsername("wss40");
        
        java.util.Map<String, Object> config = new java.util.TreeMap<String, Object>();
        config.put(WSHandlerConstants.SIG_PROP_FILE, "wss40.properties");
        config.put(WSHandlerConstants.PW_CALLBACK_REF, callbackHandler);
        config.put(WSHandlerConstants.SIG_KEY_ID, "Thumbprint");
        reqData.setMsgContext(config);
        
        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        HandlerAction action = new HandlerAction(WSConstants.DKT_SIGN);
        handler.send(
            doc, 
            reqData, 
            Collections.singletonList(action),
            true
        );
        String outputString = 
            XMLUtils.PrettyDocumentToString(doc);
        Assert.assertTrue(outputString.contains(ConversationConstants.WSC_NS_05_12));
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        
        verify(doc);
    }
    
    @org.junit.Test
    public void testSignatureThumbprintSHA1OldNamespace() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        reqData.setUsername("wss40");
        
        java.util.Map<String, Object> config = new java.util.TreeMap<String, Object>();
        config.put(WSHandlerConstants.SIG_PROP_FILE, "wss40.properties");
        config.put(WSHandlerConstants.PW_CALLBACK_REF, callbackHandler);
        config.put(WSHandlerConstants.SIG_KEY_ID, "Thumbprint");
        config.put(WSHandlerConstants.USE_2005_12_NAMESPACE, "false");
        reqData.setMsgContext(config);
        
        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        HandlerAction action = new HandlerAction(WSConstants.DKT_SIGN);
        handler.send(
            doc, 
            reqData, 
            Collections.singletonList(action),
            true
        );
        String outputString = 
            XMLUtils.PrettyDocumentToString(doc);
        Assert.assertTrue(outputString.contains(ConversationConstants.WSC_NS_05_02));
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        
        verify(doc);
    }
    
    @org.junit.Test
    public void testSignatureThumbprintSHA1StrongDigest() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        reqData.setUsername("wss40");
        
        java.util.Map<String, Object> config = new java.util.TreeMap<String, Object>();
        config.put(WSHandlerConstants.SIG_PROP_FILE, "wss40.properties");
        config.put(WSHandlerConstants.PW_CALLBACK_REF, callbackHandler);
        config.put(WSHandlerConstants.SIG_DIGEST_ALGO, WSConstants.SHA256);
        config.put(WSHandlerConstants.SIG_KEY_ID, "Thumbprint");
        reqData.setMsgContext(config);
        
        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        HandlerAction action = new HandlerAction(WSConstants.DKT_SIGN);
        handler.send(
            doc, 
            reqData, 
            Collections.singletonList(action),
            true
        );
        String outputString = 
            XMLUtils.PrettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        
        verify(doc);
    }

    @org.junit.Test
    public void testSignatureSKI() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        reqData.setUsername("wss40");
        
        java.util.Map<String, Object> config = new java.util.TreeMap<String, Object>();
        config.put(WSHandlerConstants.SIG_PROP_FILE, "wss40.properties");
        config.put(WSHandlerConstants.PW_CALLBACK_REF, callbackHandler);
        config.put(WSHandlerConstants.SIG_KEY_ID, "SKIKeyIdentifier");
        reqData.setMsgContext(config);
        
        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        HandlerAction action = new HandlerAction(WSConstants.DKT_SIGN);
        handler.send(
            doc, 
            reqData, 
            Collections.singletonList(action),
            true
        );
        String outputString = 
            XMLUtils.PrettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        
        verify(doc);
    }

    @org.junit.Test
    public void testSignatureX509() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        reqData.setUsername("wss40");
        
        java.util.Map<String, Object> config = new java.util.TreeMap<String, Object>();
        config.put(WSHandlerConstants.SIG_PROP_FILE, "wss40.properties");
        config.put(WSHandlerConstants.PW_CALLBACK_REF, callbackHandler);
        config.put(WSHandlerConstants.DERIVED_TOKEN_REFERENCE, "DirectReference");
        config.put(WSHandlerConstants.SIG_KEY_ID, "X509KeyIdentifier");
        reqData.setMsgContext(config);
        
        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        HandlerAction action = new HandlerAction(WSConstants.DKT_SIGN);
        handler.send(
            doc, 
            reqData, 
            Collections.singletonList(action),
            true
        );
        String outputString = 
            XMLUtils.PrettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        
        verify(doc);
    }
    
    @org.junit.Test
    public void testSignatureEncryptedKeyThumbprintSHA1() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        reqData.setUsername("wss40");
        
        java.util.Map<String, Object> config = new java.util.TreeMap<String, Object>();
        config.put(WSHandlerConstants.SIG_PROP_FILE, "wss40.properties");
        config.put(WSHandlerConstants.PW_CALLBACK_REF, callbackHandler);
        config.put(WSHandlerConstants.DERIVED_TOKEN_REFERENCE, "EncryptedKey");
        config.put(WSHandlerConstants.SIG_KEY_ID, "Thumbprint");
        reqData.setMsgContext(config);
        
        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        HandlerAction action = new HandlerAction(WSConstants.DKT_SIGN);
        handler.send(
            doc, 
            reqData, 
            Collections.singletonList(action),
            true
        );
        String outputString = 
            XMLUtils.PrettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        
        verify(doc);
    }
    
    @org.junit.Test
    public void testSignatureSCT() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        
        // Generate a Key
        SecretKeyCallbackHandler secretKeyCallbackHandler = new SecretKeyCallbackHandler();
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey key = keyGen.generateKey();
        byte[] keyData = key.getEncoded();
        secretKeyCallbackHandler.setOutboundSecret(keyData);
        
        java.util.Map<String, Object> config = new java.util.TreeMap<String, Object>();
        config.put(WSHandlerConstants.PW_CALLBACK_REF, secretKeyCallbackHandler);
        config.put(WSHandlerConstants.DERIVED_TOKEN_REFERENCE, "SecurityContextToken");
        reqData.setMsgContext(config);
        
        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        HandlerAction action = new HandlerAction(WSConstants.DKT_SIGN);
        handler.send(
            doc, 
            reqData, 
            Collections.singletonList(action),
            true
        );
        String outputString = 
            XMLUtils.PrettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        
        verify(doc, secretKeyCallbackHandler);
    }

    private List<WSSecurityEngineResult> verify(Document doc) throws Exception {
        return verify(doc, callbackHandler);
    }

    private List<WSSecurityEngineResult> verify(Document doc, CallbackHandler cbHandler) throws Exception {
        WSSecurityEngine secEngine = new WSSecurityEngine();
        List<WSSecurityEngineResult> results = 
            secEngine.processSecurityHeader(doc, null, cbHandler, crypto);
        String outputString = 
            XMLUtils.PrettyDocumentToString(doc);
        assertTrue(outputString.indexOf("counter_port_type") > 0 ? true : false);
        
        return results;
    }

}
