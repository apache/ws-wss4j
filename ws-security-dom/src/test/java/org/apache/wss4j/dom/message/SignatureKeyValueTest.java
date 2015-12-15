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

import org.apache.wss4j.common.principal.PublicKeyPrincipal;
import org.w3c.dom.Document;
import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerResult;

/**
 * This class tests signing where the the public key is transmitted in the message via
 * a ds:KeyInfo/ds:KeyValue element. Although this isn't strictly recommended for use in
 * WS-Security, it's necessary to support it for WCF interop.
 */
public class SignatureKeyValueTest extends org.junit.Assert {
    private static final org.slf4j.Logger LOG = 
        org.slf4j.LoggerFactory.getLogger(SignatureKeyValueTest.class);
    private Crypto crypto = null;
    
    @org.junit.AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }
    
    public SignatureKeyValueTest() throws Exception {
        WSSConfig.init();
        crypto = CryptoFactory.getInstance("wss40.properties");
    }

    /**
     * Successful RSAKeyValue test.
     */
    @org.junit.Test
    public void testRSAKeyValue() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("wss40", "security");
        builder.setKeyIdentifierType(WSConstants.KEY_VALUE);
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        Document signedDoc = builder.build(doc, crypto, secHeader);

        String outputString = 
            XMLUtils.PrettyDocumentToString(signedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains("RSAKeyValue"));
        
        WSSecurityEngine secEngine = new WSSecurityEngine();
        RequestData data = new RequestData();
        data.setSigVerCrypto(crypto);
        data.setIgnoredBSPRules(Collections.singletonList(BSPRule.R5417));
        final WSHandlerResult results = 
            secEngine.processSecurityHeader(signedDoc, data);

        WSSecurityEngineResult actionResult = 
            results.getActionResults().get(WSConstants.SIGN).get(0);
        assertTrue(actionResult != null);
        
        java.security.Principal principal = 
            (java.security.Principal)actionResult.get(WSSecurityEngineResult.TAG_PRINCIPAL);
        assertTrue(principal instanceof PublicKeyPrincipal);
        java.security.PublicKey publicKey = 
            ((PublicKeyPrincipal)principal).getPublicKey();
        assertTrue(publicKey instanceof java.security.interfaces.RSAPublicKey);
        
    }
    
    
    /**
     * Failed RSAKeyValue test, where a message is signed using a key-pair which doesn't
     * correspond to the public key in the "trust"-store.
     */
    @org.junit.Test
    public void testBadRSAKeyValue() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("wss86", "security");
        builder.setKeyIdentifierType(WSConstants.KEY_VALUE);
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        Document signedDoc = 
            builder.build(doc, CryptoFactory.getInstance("wss86.properties"), secHeader);

        String outputString = 
            XMLUtils.PrettyDocumentToString(signedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains("RSAKeyValue"));
        
        try {
            WSSecurityEngine secEngine = new WSSecurityEngine();
            RequestData data = new RequestData();
            data.setSigVerCrypto(crypto);
            data.setIgnoredBSPRules(Collections.singletonList(BSPRule.R5417));
            secEngine.processSecurityHeader(signedDoc, data);
            fail("Failure expected on bad public key");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.FAILED_AUTHENTICATION); 
        }
        
    }
    
    
    /**
     * Successful DSAKeyValue test.
     */
    @org.junit.Test
    public void testDSAKeyValue() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("wss40DSA", "security");
        builder.setKeyIdentifierType(WSConstants.KEY_VALUE);
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        Document signedDoc = builder.build(doc, crypto, secHeader);

        String outputString = 
            XMLUtils.PrettyDocumentToString(signedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains("DSAKeyValue"));
        
        WSSecurityEngine secEngine = new WSSecurityEngine();
        RequestData data = new RequestData();
        data.setSigVerCrypto(crypto);
        data.setIgnoredBSPRules(Collections.singletonList(BSPRule.R5417));
        final WSHandlerResult results = 
            secEngine.processSecurityHeader(signedDoc, data);
        
        WSSecurityEngineResult actionResult = 
            results.getActionResults().get(WSConstants.SIGN).get(0);
        assertTrue(actionResult != null);
        
        java.security.Principal principal = 
            (java.security.Principal)actionResult.get(WSSecurityEngineResult.TAG_PRINCIPAL);
        assertTrue(principal instanceof PublicKeyPrincipal);
        java.security.PublicKey publicKey = 
            ((PublicKeyPrincipal)principal).getPublicKey();
        assertTrue(publicKey instanceof java.security.interfaces.DSAPublicKey);
    }
    
}
