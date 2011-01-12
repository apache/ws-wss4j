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

import org.apache.ws.security.saml.SAMLIssuerFactory;
import org.apache.ws.security.saml.SAMLIssuer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.common.CustomHandler;
import org.apache.ws.security.common.KeystoreCallbackHandler;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;

import javax.security.auth.callback.CallbackHandler;
import java.util.List;

import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * Test-case for sending and processing an signed SAML Assertion.
 * 
 * @author Davanum Srinivas (dims@yahoo.com)
 */
public class SignedSamlTokenTest extends org.junit.Assert {
    private static final Log LOG = LogFactory.getLog(SignedSamlTokenTest.class);
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private CallbackHandler callbackHandler = new KeystoreCallbackHandler();
    private Crypto crypto = CryptoFactory.getInstance("crypto.properties");

    /**
     * Test that creates, sends and processes an signed SAML assertion.
     */
    @org.junit.Test
    public void testSAMLSignedSenderVouches() throws Exception {
        SAMLIssuer saml = SAMLIssuerFactory.getInstance("saml_sv.properties");
        AssertionWrapper assertion = saml.newAssertion();

        WSSecSignatureSAML wsSign = new WSSecSignatureSAML();
        wsSign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        
        LOG.info("Before SAMLSignedSenderVouches....");
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document signedDoc = 
            wsSign.build(
                doc, null, assertion, crypto, "16c73ab6-b892-458f-abf5-2f875f74882e", 
                "security", secHeader
            );
        LOG.info("After SAMLSignedSenderVouches....");

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
     * Test that creates, sends and processes an signed SAML assertion using a KeyIdentifier
     * instead of direct reference.
     */
    @org.junit.Test
    public void testSAMLSignedSenderVouchesKeyIdentifier() throws Exception {
        SAMLIssuer saml = SAMLIssuerFactory.getInstance("saml_sv.properties");
        AssertionWrapper assertion = saml.newAssertion();

        WSSecSignatureSAML wsSign = new WSSecSignatureSAML();
        wsSign.setKeyIdentifierType(WSConstants.X509_KEY_IDENTIFIER);
        
        LOG.info("Before SAMLSignedSenderVouches....");
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document signedDoc = 
            wsSign.build(
                doc, null, assertion, crypto, "16c73ab6-b892-458f-abf5-2f875f74882e", 
                "security", secHeader
            );
        LOG.info("After SAMLSignedSenderVouches....");

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
        
        LOG.info("Before SAMLSignedSenderVouches....");

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document signedDoc = 
            wsSign.build(
                 doc, null, assertion, crypto, "16c73ab6-b892-458f-abf5-2f875f74882e", 
                 "security", secHeader
             );
        LOG.info("After SAMLSignedSenderVouches....");

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
        
        //
        // Negative test
        //
        msgContext.put(WSHandlerConstants.SIG_PROP_FILE, "crypto.properties.na");
        reqData.setMsgContext(msgContext);
        
        handler = new CustomHandler();
        try {
            handler.receive(WSConstants.ST_SIGNED, reqData);
            fail("Failure expected on a bad crypto properties file");
        } catch (RuntimeException ex) {
            // expected
        }
    }
    
    /**
     * Test that creates, sends and processes an signed SAML assertion.
     */
    @org.junit.Test
    public void testSAMLSignedKeyHolder() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        
        SAMLIssuer saml = SAMLIssuerFactory.getInstance("saml_hok.properties");
        AssertionWrapper assertion = saml.newAssertion();

        WSSecSignatureSAML wsSign = new WSSecSignatureSAML();
        wsSign.setDigestAlgo("http://www.w3.org/2001/04/xmlenc#sha256");
        wsSign.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        wsSign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        wsSign.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        LOG.info("Before SAMLSignedKeyHolder....");
        
        //
        // set up for keyHolder
        //
        Document signedDoc = wsSign.build(doc, crypto, assertion, null, null, null, secHeader);
        LOG.info("After SAMLSignedKeyHolder....");

        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed SAML message (key holder):");
            LOG.debug(outputString);
        }
        assertTrue(outputString.indexOf("http://www.w3.org/2001/04/xmlenc#sha256") != -1);
        assertTrue(outputString.indexOf("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256") != -1);
        
        List<WSSecurityEngineResult> results = verify(signedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
    }
    
    /**
     * Test that creates, sends and processes a signed SAML assertion containing
     * only key material and not an entire X509Certificate.
     */
    @org.junit.Test
    public void testSAMLSignedKeyHolderSendKeyValue() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        
        SAMLIssuer saml = SAMLIssuerFactory.getInstance("saml_hok_keyvalue.properties");
        AssertionWrapper assertion = saml.newAssertion();

        WSSecSignatureSAML wsSign = new WSSecSignatureSAML();
        wsSign.setDigestAlgo("http://www.w3.org/2001/04/xmlenc#sha256");
        wsSign.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        wsSign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        wsSign.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        LOG.info("Before SAMLSignedKeyHolder....");
        
        //
        // set up for keyHolder
        //
        Document signedDoc = wsSign.build(doc, crypto, assertion, null, null, null, secHeader);
        LOG.info("After SAMLSignedKeyHolder....");

        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed SAML message (key holder):");
            LOG.debug(outputString);
        }
        assertTrue(outputString.indexOf("http://www.w3.org/2001/04/xmlenc#sha256") != -1);
        assertTrue(outputString.indexOf("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256") != -1);
        assertTrue(outputString.indexOf("KeyValue") != -1);
        assertTrue(outputString.indexOf("X509Certificate") == -1);
        
        List<WSSecurityEngineResult> results = verify(signedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
    }
    
    
    /**
     * Test that creates, sends and processes an signed SAML assertion using a KeyIdentifier
     * instead of direct reference.
     */
    @org.junit.Test
    public void testSAMLSignedKeyHolderKeyIdentifier() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        
        SAMLIssuer saml = SAMLIssuerFactory.getInstance("saml_hok.properties");
        AssertionWrapper assertion = saml.newAssertion();

        WSSecSignatureSAML wsSign = new WSSecSignatureSAML();
        wsSign.setKeyIdentifierType(WSConstants.X509_KEY_IDENTIFIER);
        wsSign.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        LOG.info("Before SAMLSignedKeyHolder....");
        
        //
        // set up for keyHolder
        //
        Document signedDoc = wsSign.build(doc, crypto, assertion, null, null, null, secHeader);
        LOG.info("After SAMLSignedKeyHolder....");

        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed SAML message (key holder):");
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
     * Test that creates a signed SAML Assertion using HOK, but then modifies the signature
     * object by replacing the enveloped transform with the exclusive c14n transform. 
     * The signature validation should then fail - the enveloped transform is mandatory for
     * a signed assertion.
     */
    @org.junit.Test
    public void testSAMLSignedKeyHolderSigModified() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        
        SAMLIssuer saml = SAMLIssuerFactory.getInstance("saml_hok.properties");
        AssertionWrapper assertion = saml.newAssertion();

        WSSecSignatureSAML wsSign = new WSSecSignatureSAML();
        wsSign.setKeyIdentifierType(WSConstants.X509_KEY_IDENTIFIER);
        wsSign.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        Document signedDoc = wsSign.build(doc, crypto, assertion, null, null, null, secHeader);
        
        //
        // Modify the assertion
        //
        Element envelope = signedDoc.getDocumentElement();
        NodeList list = envelope.getElementsByTagNameNS(WSConstants.SAML_NS, "Assertion");
        Element assertionElement = (org.w3c.dom.Element)list.item(0);
        list = assertionElement.getElementsByTagNameNS(WSConstants.SIG_NS, "Signature");
        Element sigElement = (org.w3c.dom.Element)list.item(0);
        list = sigElement.getElementsByTagNameNS(WSConstants.SIG_NS, "Transform");
        Element transformElement = (org.w3c.dom.Element)list.item(0);
        transformElement.setAttributeNS(null, "Algorithm", WSConstants.C14N_EXCL_OMIT_COMMENTS);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed (modified) SAML message (key holder):");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        try {
            verify(signedDoc);
            fail("Expected failure on a modified signature");
        } catch (WSSecurityException ex) {
            // expected
        }
    }
    
    /**
     * Test that creates a signed SAML Assertion using HOK, but then modifies the assertion.
     * The signature verification should then fail.
     */
    @org.junit.Test
    public void testSAMLSignedKeyHolderKeyModified() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        
        SAMLIssuer saml = SAMLIssuerFactory.getInstance("saml_hok.properties");
        AssertionWrapper assertion = saml.newAssertion();

        WSSecSignatureSAML wsSign = new WSSecSignatureSAML();
        wsSign.setKeyIdentifierType(WSConstants.X509_KEY_IDENTIFIER);
        wsSign.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        Document signedDoc = wsSign.build(doc, crypto, assertion, null, null, null, secHeader);
        
        //
        // Modify the assertion
        //
        Element envelope = signedDoc.getDocumentElement();
        NodeList list = envelope.getElementsByTagNameNS(WSConstants.SAML_NS, "Assertion");
        Element assertionElement = (org.w3c.dom.Element)list.item(0);
        assertionElement.setAttributeNS(null, "MinorVersion", "5");
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed (modified) SAML message (key holder):");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        try {
            verify(signedDoc);
            fail("Expected failure on a modified signature");
        } catch (WSSecurityException ex) {
            // expected
        }
    }

    
    /**
     * Verifies the soap envelope
     * 
     * @param doc
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
