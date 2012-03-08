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

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.common.KeystoreCallbackHandler;
import org.apache.ws.security.common.SAML1CallbackHandler;
import org.apache.ws.security.common.SAML2CallbackHandler;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.WSSecSAMLToken;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.apache.ws.security.saml.ext.SAMLParms;
import org.apache.ws.security.saml.ext.builder.SAML1Constants;
import org.apache.ws.security.saml.ext.builder.SAML2Constants;
import org.apache.ws.security.util.WSSecurityUtil;

import org.w3c.dom.Document;

import java.util.List;

/**
 * Test-case for sending and processing a signed (holder-of-key) SAML Assertion. These tests
 * just cover the case of creating and signing the Assertion, and not using the credential 
 * information in the SAML Subject to sign the SOAP body.
 */
public class SamlTokenHOKTest extends org.junit.Assert {
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(SamlTokenHOKTest.class);
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private Crypto crypto = null;
    
    public SamlTokenHOKTest() throws Exception {
        WSSConfig.init();
        crypto = CryptoFactory.getInstance("crypto.properties");
    }

    /**
     * Test that creates, sends and processes a signed SAML 1.1 authentication assertion.
     */
    @org.junit.Test
    public void testSAML1AuthnAssertion() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML1Constants.CONF_HOLDER_KEY);
        callbackHandler.setIssuer("www.example.com");
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);
        assertion.signAssertion("16c73ab6-b892-458f-abf5-2f875f74882e", "security", crypto, false);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document signedDoc = wsSign.build(doc, assertion, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 1.1 Authn Assertion (holder-of-key):");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(signedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_SIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
        assertTrue(receivedAssertion.isSigned());
        assertNotNull(receivedAssertion.assertionToString());
    }
    
    /**
     * Test that creates, sends and processes a signed SAML 1 authentication assertion, where
     * the configuration is loaded from a properties file
     */
    @org.junit.Test
    public void testSAML1AuthnAssertionFromProperties() throws Exception {
        SAMLIssuer saml = SAMLIssuerFactory.getInstance("saml_hok.properties");
        AssertionWrapper assertion = saml.newAssertion();

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document signedDoc = wsSign.build(doc, assertion, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 1.1 Authn Assertion (holder-of-key):");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(signedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_SIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
        assertTrue(receivedAssertion.isSigned());
    }
    
    /**
     * Test that creates, sends and processes a signed SAML 1.1 attribute assertion.
     */
    @org.junit.Test
    public void testSAML1AttrAssertion() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML1Constants.CONF_HOLDER_KEY);
        callbackHandler.setIssuer("www.example.com");
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);
        assertion.signAssertion("16c73ab6-b892-458f-abf5-2f875f74882e", "security", crypto, false);


        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document signedDoc = wsSign.build(doc, assertion, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 1.1 Attr Assertion (holder-of-key):");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        Crypto decCrypto = CryptoFactory.getInstance("wss40.properties");
        List<WSSecurityEngineResult> results = 
            secEngine.processSecurityHeader(doc, null, new KeystoreCallbackHandler(), crypto, decCrypto);
        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
        assertTrue(outputString.indexOf("counter_port_type") > 0 ? true : false);
        
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_SIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
        assertTrue(receivedAssertion.isSigned());
    }
    
    /**
     * Test that creates, sends and processes an unsigned SAML 2 authentication assertion.
     */
    @org.junit.Test
    public void testSAML2AuthnAssertion() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_HOLDER_KEY);
        callbackHandler.setIssuer("www.example.com");
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);
        assertion.signAssertion("16c73ab6-b892-458f-abf5-2f875f74882e", "security", crypto, false);

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, assertion, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 2 Authn Assertion (holder-of-key):");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(unsignedDoc);
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(unsignedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_SIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
        assertTrue(receivedAssertion.isSigned());
    }
    
    /**
     * Test that creates, sends and processes an unsigned SAML 2 attribute assertion.
     */
    @org.junit.Test
    public void testSAML2AttrAssertion() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_HOLDER_KEY);
        callbackHandler.setIssuer("www.example.com");
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);
        assertion.signAssertion("16c73ab6-b892-458f-abf5-2f875f74882e", "security", crypto, false);


        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document unsignedDoc = wsSign.build(doc, assertion, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 2 Attr Assertion (holder-of-key):");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(unsignedDoc);
            LOG.debug(outputString);
        }
        
        Crypto decCrypto = CryptoFactory.getInstance("wss40.properties");
        List<WSSecurityEngineResult> results = 
            secEngine.processSecurityHeader(doc, null, new KeystoreCallbackHandler(), crypto, decCrypto);
        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
        assertTrue(outputString.indexOf("counter_port_type") > 0 ? true : false);
        
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_SIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
    }

    /**
     * Verifies the soap envelope
     * <p/>
     * 
     * @param envelope 
     * @throws Exception Thrown when there is a problem in verification
     */
    private List<WSSecurityEngineResult> verify(Document doc) throws Exception {
        List<WSSecurityEngineResult> results = 
            secEngine.processSecurityHeader(doc, null, null, crypto);
        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
        assertTrue(outputString.indexOf("counter_port_type") > 0 ? true : false);
        return results;
    }

}
