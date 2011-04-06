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

import org.apache.ws.security.PublicKeyPrincipal;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;

import java.util.List;

/**
 * This class tests signing where the the public key is transmitted in the message via
 * a ds:KeyInfo/ds:KeyValue element. Although this isn't strictly recommended for use in
 * WS-Security, it's necessary to support it for WCF interop.
 */
public class SignatureKeyValueTest extends org.junit.Assert {
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(SignatureKeyValueTest.class);
    private Crypto crypto = null;
    
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
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, crypto, secHeader);

        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        assertTrue(outputString.indexOf("RSAKeyValue") != -1);
        
        WSSecurityEngine secEngine = new WSSecurityEngine();
        WSSConfig config = WSSConfig.getNewInstance();
        config.setWsiBSPCompliant(false);
        secEngine.setWssConfig(config);
        final List<WSSecurityEngineResult> results = 
            secEngine.processSecurityHeader(signedDoc, null, null, crypto);

        WSSecurityEngineResult actionResult = 
            WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN);
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
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = 
            builder.build(doc, CryptoFactory.getInstance("wss86.properties"), secHeader);

        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        assertTrue(outputString.indexOf("RSAKeyValue") != -1);
        
        try {
            WSSecurityEngine secEngine = new WSSecurityEngine();
            WSSConfig config = WSSConfig.getNewInstance();
            config.setWsiBSPCompliant(false);
            secEngine.setWssConfig(config);
            secEngine.processSecurityHeader(signedDoc, null, null, crypto);
            fail("Failure expected on bad public key");
        } catch (Exception ex) {
            // expected
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
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, crypto, secHeader);

        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        assertTrue(outputString.indexOf("DSAKeyValue") != -1);
        
        WSSecurityEngine secEngine = new WSSecurityEngine();
        WSSConfig config = WSSConfig.getNewInstance();
        config.setWsiBSPCompliant(false);
        secEngine.setWssConfig(config);
        final List<WSSecurityEngineResult> results = 
            secEngine.processSecurityHeader(signedDoc, null, null, crypto);
        
        WSSecurityEngineResult actionResult = 
            WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN);
        assertTrue(actionResult != null);
        
        java.security.Principal principal = 
            (java.security.Principal)actionResult.get(WSSecurityEngineResult.TAG_PRINCIPAL);
        assertTrue(principal instanceof PublicKeyPrincipal);
        java.security.PublicKey publicKey = 
            ((PublicKeyPrincipal)principal).getPublicKey();
        assertTrue(publicKey instanceof java.security.interfaces.DSAPublicKey);
    }
    
}
