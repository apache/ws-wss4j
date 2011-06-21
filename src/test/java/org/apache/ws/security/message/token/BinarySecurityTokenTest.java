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

package org.apache.ws.security.message.token;

import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.components.crypto.CryptoType;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * This is a test for constructing and processing BinarySecurityTokens.
 */
public class BinarySecurityTokenTest extends org.junit.Assert {
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(BinarySecurityTokenTest.class);
    private Crypto crypto = null;
    
    public BinarySecurityTokenTest() throws Exception {
        crypto = CryptoFactory.getInstance("wss40.properties");
    }

    /**
     * A unit test for an X.509 BinarySecurityToken
     */
    @org.junit.Test
    public void testX509() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        X509Security bst = new X509Security(doc);
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("wss40");
        X509Certificate[] certs = crypto.getX509Certificates(cryptoType);
        bst.setX509Certificate(certs[0]);
        
        WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), bst.getElement());
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("BST output");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        
        WSSConfig config = WSSConfig.getNewInstance();
        config.setWsiBSPCompliant(true);
        WSSecurityEngine secEngine = new WSSecurityEngine();
        secEngine.setWssConfig(config);
        List<WSSecurityEngineResult> results = 
            secEngine.processSecurityHeader(doc, null, null, crypto);
        
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.BST);
        BinarySecurity token =
            (BinarySecurity)actionResult.get(WSSecurityEngineResult.TAG_BINARY_SECURITY_TOKEN);
        assertNotNull(token);
        
        BinarySecurity clone = new BinarySecurity(token.getElement());
        assertTrue(clone.equals(token));
        assertTrue(clone.hashCode() == token.hashCode());
    }
    
    /**
     * A unit test for an PKIPath BinarySecurityToken
     */
    @org.junit.Test
    public void testPKIPath() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        PKIPathSecurity bst = new PKIPathSecurity(doc);
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("wss40");
        X509Certificate[] certs = crypto.getX509Certificates(cryptoType);
        bst.setX509Certificates(certs, crypto);
        
        WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), bst.getElement());
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("PKIPath output");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        
        WSSConfig config = WSSConfig.getNewInstance();
        config.setWsiBSPCompliant(true);
        WSSecurityEngine secEngine = new WSSecurityEngine();
        secEngine.setWssConfig(config);
        List<WSSecurityEngineResult> results = 
            secEngine.processSecurityHeader(doc, null, null, crypto);
        
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.BST);
        PKIPathSecurity token =
            (PKIPathSecurity)actionResult.get(WSSecurityEngineResult.TAG_BINARY_SECURITY_TOKEN);
        assertNotNull(token);
    }
    
    /**
     * A unit test for a custom BinarySecurityToken
     */
    @org.junit.Test
    public void testCustomToken() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        BinarySecurity bst = new BinarySecurity(doc);
        bst.setToken("12435677".getBytes());
        
        WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), bst.getElement());
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Custom Token output");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        
        WSSConfig config = WSSConfig.getNewInstance();
        config.setWsiBSPCompliant(true);
        WSSecurityEngine secEngine = new WSSecurityEngine();
        secEngine.setWssConfig(config);
        // Processing should fail as we have no ValueType attribute
        try {
            secEngine.processSecurityHeader(doc, null, null, crypto);
            fail("Expected failure on no ValueType");
        } catch (WSSecurityException ex) {
            // expected
        }
        
        doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        bst = new BinarySecurity(doc);
        bst.setToken("12435677".getBytes());
        bst.setValueType("http://custom_value_Type");
        secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), bst.getElement());
        
        List<WSSecurityEngineResult> results = 
            secEngine.processSecurityHeader(doc, null, null, crypto);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.BST);
        BinarySecurity token =
            (BinarySecurity)actionResult.get(WSSecurityEngineResult.TAG_BINARY_SECURITY_TOKEN);
        assertNotNull(token);
    }
    
}
