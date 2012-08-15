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
import org.apache.ws.security.WSDataRef;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.common.CustomHandler;
import org.apache.ws.security.common.KeystoreCallbackHandler;
import org.apache.ws.security.common.SAML1CallbackHandler;
import org.apache.ws.security.common.SAML2CallbackHandler;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.apache.ws.security.saml.ext.SAMLParms;
import org.apache.ws.security.saml.ext.builder.SAML1Constants;
import org.apache.ws.security.saml.ext.builder.SAML2Constants;
import org.apache.ws.security.util.WSSecurityUtil;

import org.w3c.dom.Document;

import java.util.List;

import javax.security.auth.callback.CallbackHandler;

/**
 * Test-case for sending and processing a signed (sender vouches) SAML Assertion.
 */
public class SamlTokenSVTest extends org.junit.Assert {
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(SamlTokenSVTest.class);
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private CallbackHandler callbackHandler = new KeystoreCallbackHandler();
    private Crypto crypto = null;
    
    public SamlTokenSVTest() throws Exception {
        WSSConfig.init();
        crypto = CryptoFactory.getInstance("crypto.properties");
    }
    
    /**
     * Test that creates, sends and processes a signed SAML 1.1 authentication assertion.
     */
    @org.junit.Test
    @SuppressWarnings("unchecked")
    public void testSAML1AuthnAssertion() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML1Constants.CONF_SENDER_VOUCHES);
        callbackHandler.setIssuer("www.example.com");
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);
        
        WSSecSignatureSAML wsSign = new WSSecSignatureSAML();
        wsSign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document signedDoc = 
            wsSign.build(
                doc, null, assertion, crypto, "16c73ab6-b892-458f-abf5-2f875f74882e", 
                "security", secHeader
            );

        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 1.1 Authn Assertion (sender vouches):");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        // Test we processed a SAML assertion
        List<WSSecurityEngineResult> results = verify(signedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
        
        // Test we processed a signature (SAML assertion + SOAP body)
        actionResult = WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN);
        assertTrue(actionResult != null);
        assertFalse(actionResult.isEmpty());
        final List<WSDataRef> refs =
            (List<WSDataRef>) actionResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
        assertTrue(refs.size() == 2);
        
        WSDataRef wsDataRef = (WSDataRef)refs.get(0);
        String xpath = wsDataRef.getXpath();
        assertEquals("/SOAP-ENV:Envelope/SOAP-ENV:Body", xpath);
        
        wsDataRef = (WSDataRef)refs.get(1);
        xpath = wsDataRef.getXpath();
        assertEquals("/SOAP-ENV:Envelope/SOAP-ENV:Header/wsse:Security/saml1:Assertion", xpath);
    }
    
    /**
     * Test that creates, sends and processes a signed SAML 1 authentication assertion, where
     * the configuration is loaded from a properties file
     */
    @org.junit.Test
    @SuppressWarnings("unchecked")
    public void testSAML1AuthnAssertionFromProperties() throws Exception {
        SAMLIssuer saml = SAMLIssuerFactory.getInstance("saml_sv.properties");
        AssertionWrapper assertion = saml.newAssertion();

        WSSecSignatureSAML wsSign = new WSSecSignatureSAML();
        wsSign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document signedDoc = 
            wsSign.build(
                doc, null, assertion, crypto, "16c73ab6-b892-458f-abf5-2f875f74882e", 
                "security", secHeader
            );

        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 1.1 Authn Assertion (sender vouches):");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        // Test we processed a SAML assertion
        List<WSSecurityEngineResult> results = verify(signedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
        
        // Test we processed a signature (SAML assertion + SOAP body)
        actionResult = WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN);
        assertTrue(actionResult != null);
        assertFalse(actionResult.isEmpty());
        final List<WSDataRef> refs =
            (List<WSDataRef>) actionResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
        assertTrue(refs.size() == 2);
        
        WSDataRef wsDataRef = (WSDataRef)refs.get(0);
        String xpath = wsDataRef.getXpath();
        assertEquals("/SOAP-ENV:Envelope/SOAP-ENV:Body", xpath);
        
        wsDataRef = (WSDataRef)refs.get(1);
        xpath = wsDataRef.getXpath();
        assertEquals("/SOAP-ENV:Envelope/SOAP-ENV:Header/wsse:Security/saml1:Assertion", xpath);
    }
    
    /**
     * Test that creates, sends and processes a signed SAML 1.1 attribute assertion.
     */
    @org.junit.Test
    @SuppressWarnings("unchecked")
    public void testSAML1AttrAssertion() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML1Constants.CONF_SENDER_VOUCHES);
        callbackHandler.setIssuer("www.example.com");
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);

        WSSecSignatureSAML wsSign = new WSSecSignatureSAML();
        wsSign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document signedDoc = 
            wsSign.build(
                doc, null, assertion, crypto, "16c73ab6-b892-458f-abf5-2f875f74882e", 
                "security", secHeader
            );

        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 1.1 Attr Assertion (sender vouches):");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        // Test we processed a SAML assertion
        List<WSSecurityEngineResult> results = verify(signedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
        
        // Test we processed a signature (SAML assertion + SOAP body)
        actionResult = WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN);
        assertTrue(actionResult != null);
        assertFalse(actionResult.isEmpty());
        final List<WSDataRef> refs =
            (List<WSDataRef>) actionResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
        assertTrue(refs.size() == 2);
        
        WSDataRef wsDataRef = (WSDataRef)refs.get(0);
        String xpath = wsDataRef.getXpath();
        assertEquals("/SOAP-ENV:Envelope/SOAP-ENV:Body", xpath);
        
        wsDataRef = (WSDataRef)refs.get(1);
        xpath = wsDataRef.getXpath();
        assertEquals("/SOAP-ENV:Envelope/SOAP-ENV:Header/wsse:Security/saml1:Assertion", xpath);
    }
    
    /**
     * Test that creates, sends and processes a signed SAML 2 authentication assertion.
     */
    @org.junit.Test
    @SuppressWarnings("unchecked")
    public void testSAML2AuthnAssertion() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_SENDER_VOUCHES);
        callbackHandler.setIssuer("www.example.com");
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);
        WSSecSignatureSAML wsSign = new WSSecSignatureSAML();
        wsSign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document signedDoc = 
            wsSign.build(
                doc, null, assertion, crypto, "16c73ab6-b892-458f-abf5-2f875f74882e", 
                "security", secHeader
            );

        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 2 Authn Assertion (sender vouches):");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        // Test we processed a SAML assertion
        List<WSSecurityEngineResult> results = verify(signedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
        
        // Test we processed a signature (SAML assertion + SOAP body)
        actionResult = WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN);
        assertTrue(actionResult != null);
        assertFalse(actionResult.isEmpty());
        final List<WSDataRef> refs =
            (List<WSDataRef>) actionResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
        assertTrue(refs.size() == 2);
        
        WSDataRef wsDataRef = (WSDataRef)refs.get(0);
        String xpath = wsDataRef.getXpath();
        assertEquals("/SOAP-ENV:Envelope/SOAP-ENV:Body", xpath);
        
        wsDataRef = (WSDataRef)refs.get(1);
        xpath = wsDataRef.getXpath();
        assertEquals("/SOAP-ENV:Envelope/SOAP-ENV:Header/wsse:Security/saml2:Assertion", xpath);
    }
    
    /**
     * Test that creates, sends and processes a signed SAML 2 attribute assertion.
     */
    @org.junit.Test
    @SuppressWarnings("unchecked")
    public void testSAML2AttrAssertion() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_SENDER_VOUCHES);
        callbackHandler.setIssuer("www.example.com");
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);

        WSSecSignatureSAML wsSign = new WSSecSignatureSAML();
        wsSign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document signedDoc = 
            wsSign.build(
                doc, null, assertion, crypto, "16c73ab6-b892-458f-abf5-2f875f74882e", 
                "security", secHeader
            );

        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 2 Attr Assertion (sender vouches):");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        // Test we processed a SAML assertion
        List<WSSecurityEngineResult> results = verify(signedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
        
        // Test we processed a signature (SAML assertion + SOAP body)
        actionResult = WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN);
        assertTrue(actionResult != null);
        assertFalse(actionResult.isEmpty());
        final List<WSDataRef> refs =
            (List<WSDataRef>) actionResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
        assertTrue(refs.size() == 2);
        
        WSDataRef wsDataRef = (WSDataRef)refs.get(0);
        String xpath = wsDataRef.getXpath();
        assertEquals("/SOAP-ENV:Envelope/SOAP-ENV:Body", xpath);
        
        wsDataRef = (WSDataRef)refs.get(1);
        xpath = wsDataRef.getXpath();
        assertEquals("/SOAP-ENV:Envelope/SOAP-ENV:Header/wsse:Security/saml2:Assertion", xpath);
    }
    
    /**
     * Test the default issuer class as specified in SAMLIssuerFactory. The configuration
     * file "saml3.saml_sv_noissuer.properties" has no "org.apache.ws.security.saml.issuerClass"
     * property, and so the default value is used (A bad value was previously used for the
     * default value).
     */
    @org.junit.Test
    public void testDefaultIssuerClass() throws Exception {
        SAMLIssuer saml = SAMLIssuerFactory.getInstance("saml_sv_noissuer.properties");
        AssertionWrapper assertion = saml.newAssertion();

        WSSecSignatureSAML wsSign = new WSSecSignatureSAML();
        wsSign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document signedDoc = 
            wsSign.build(
                 doc, null, assertion, crypto, "16c73ab6-b892-458f-abf5-2f875f74882e", 
                 "security", secHeader
             );

        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed SAML message (sender vouches):");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(signedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
    }
    
    
    /**
     * A test for WSS-62: "the crypto file not being retrieved in the doReceiverAction
     * method for the Saml Signed Token"
     * 
     * https://issues.apache.org/jira/browse/WSS-62
     */
    @org.junit.Test
    public void testWSS62() throws Exception {
        SAMLIssuer saml = SAMLIssuerFactory.getInstance("saml_sv.properties");
        AssertionWrapper assertion = saml.newAssertion();

        WSSecSignatureSAML wsSign = new WSSecSignatureSAML();
        wsSign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document signedDoc = 
            wsSign.build(
                doc, null, assertion, crypto, "16c73ab6-b892-458f-abf5-2f875f74882e", 
                "security", secHeader
            );
        //
        // Now verify it but first call Handler#doReceiverAction
        //
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        java.util.Map<String, Object> msgContext = new java.util.HashMap<String, Object>();
        msgContext.put(WSHandlerConstants.SIG_PROP_FILE, "crypto.properties");
        reqData.setMsgContext(msgContext);
        
        CustomHandler handler = new CustomHandler();
        handler.receive(WSConstants.ST_SIGNED, reqData);
        
        secEngine.processSecurityHeader(
            signedDoc, null, callbackHandler, reqData.getSigCrypto(), reqData.getDecCrypto()
        );
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
            secEngine.processSecurityHeader(doc, null, callbackHandler, crypto);
        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
        assertTrue(outputString.indexOf("counter_port_type") > 0 ? true : false);
        return results;
    }

}
