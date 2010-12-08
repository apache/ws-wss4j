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
import org.apache.ws.security.common.CustomHandler;
import org.apache.ws.security.common.KeystoreCallbackHandler;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;

import org.opensaml.SAMLAssertion;

import javax.security.auth.callback.CallbackHandler;
import java.util.List;

/**
 * Test-case for sending and processing an signed SAML Assertion.
 * 
 * @author Davanum Srinivas (dims@yahoo.com)
 */
public class SignedSamlTokenTest extends org.junit.Assert {
    private static final Log LOG = LogFactory.getLog(SignedSamlTokenTest.class);
    private static final String SOAPMSG = 
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" 
        + "<SOAP-ENV:Envelope "
        +   "xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" "
        +   "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" "
        +   "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" 
        +   "<SOAP-ENV:Body>" 
        +      "<ns1:testMethod xmlns:ns1=\"uri:LogTestService2\"></ns1:testMethod>" 
        +   "</SOAP-ENV:Body>" 
        + "</SOAP-ENV:Envelope>";

    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private CallbackHandler callbackHandler = new KeystoreCallbackHandler();
    private Crypto crypto = CryptoFactory.getInstance("crypto.properties");

    /**
     * Test that creates, sends and processes an signed SAML assertion.
     */
    @org.junit.Test
    public void testSAMLSignedSenderVouches() throws Exception {
        SAMLIssuer saml = SAMLIssuerFactory.getInstance("saml.properties");

        SAMLAssertion assertion = saml.newAssertion();

        String issuerKeyName = saml.getIssuerKeyName();
        String issuerKeyPW = saml.getIssuerKeyPassword();
        Crypto issuerCrypto = saml.getIssuerCrypto();
        WSSecSignatureSAML wsSign = new WSSecSignatureSAML();
        wsSign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        
        LOG.info("Before SAMLSignedSenderVouches....");
        
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document signedDoc = 
            wsSign.build(doc, null, assertion, issuerCrypto, issuerKeyName, issuerKeyPW, secHeader);
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
        SAMLAssertion receivedAssertion = 
            (SAMLAssertion) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
    }
    
    
    /**
     * Test that creates, sends and processes an signed SAML assertion using a KeyIdentifier
     * instead of direct reference.
     */
    @org.junit.Test
    public void testSAMLSignedSenderVouchesKeyIdentifier() throws Exception {
        SAMLIssuer saml = SAMLIssuerFactory.getInstance("saml.properties");

        SAMLAssertion assertion = saml.newAssertion();

        String issuerKeyName = saml.getIssuerKeyName();
        String issuerKeyPW = saml.getIssuerKeyPassword();
        Crypto issuerCrypto = saml.getIssuerCrypto();
        WSSecSignatureSAML wsSign = new WSSecSignatureSAML();
        wsSign.setKeyIdentifierType(WSConstants.X509_KEY_IDENTIFIER);
        
        LOG.info("Before SAMLSignedSenderVouches....");
        
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document signedDoc = 
            wsSign.build(doc, null, assertion, issuerCrypto, issuerKeyName, issuerKeyPW, secHeader);
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
        SAMLAssertion receivedAssertion = 
            (SAMLAssertion) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
    }
    
    
    /**
     * Test the default issuer class as specified in SAMLIssuerFactory. The configuration
     * file "saml3.properties" has no "org.apache.ws.security.saml.issuerClass" property,
     * and so the default value is used (A bad value was previously used for the default
     * value).
     */
    @org.junit.Test
    public void testDefaultIssuerClass() throws Exception {
        SAMLIssuer saml = SAMLIssuerFactory.getInstance("saml3.properties");

        SAMLAssertion assertion = saml.newAssertion();

        String issuerKeyName = saml.getIssuerKeyName();
        String issuerKeyPW = saml.getIssuerKeyPassword();
        Crypto issuerCrypto = saml.getIssuerCrypto();
        WSSecSignatureSAML wsSign = new WSSecSignatureSAML();
        wsSign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        
        LOG.info("Before SAMLSignedSenderVouches....");

        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document signedDoc = wsSign.build(doc, null, assertion, issuerCrypto, issuerKeyName, issuerKeyPW, secHeader);
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
        SAMLAssertion receivedAssertion = 
            (SAMLAssertion) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
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
        SAMLIssuer saml = SAMLIssuerFactory.getInstance("saml.properties");

        SAMLAssertion assertion = saml.newAssertion();

        String issuerKeyName = saml.getIssuerKeyName();
        String issuerKeyPW = saml.getIssuerKeyPassword();
        Crypto issuerCrypto = saml.getIssuerCrypto();
        WSSecSignatureSAML wsSign = new WSSecSignatureSAML();
        wsSign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);

        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document signedDoc = 
            wsSign.build(doc, null, assertion, issuerCrypto, issuerKeyName, issuerKeyPW, secHeader);
        
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
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        
        SAMLIssuer saml = SAMLIssuerFactory.getInstance("saml4.properties");
        // Provide info to SAML issuer that it can construct a Holder-of-key
        // SAML token.
        saml.setInstanceDoc(doc);
        saml.setUserCrypto(crypto);
        saml.setUsername("16c73ab6-b892-458f-abf5-2f875f74882e");
        SAMLAssertion assertion = saml.newAssertion();

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
        SAMLAssertion receivedAssertion = 
            (SAMLAssertion) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
    }
    
    /**
     * Test that creates, sends and processes a signed SAML assertion containing
     * only key material and not an entire X509Certificate.
     */
    @org.junit.Test
    public void testSAMLSignedKeyHolderSendKeyValue() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        
        SAMLIssuer saml = SAMLIssuerFactory.getInstance("saml4sendKeyValue.properties");
        // Provide info to SAML issuer that it can construct a Holder-of-key
        // SAML token.
        saml.setInstanceDoc(doc);
        saml.setUserCrypto(crypto);
        saml.setUsername("16c73ab6-b892-458f-abf5-2f875f74882e");
        SAMLAssertion assertion = saml.newAssertion();

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
        SAMLAssertion receivedAssertion = 
            (SAMLAssertion) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
    }
    
    
    /**
     * Test that creates, sends and processes an signed SAML assertion using a KeyIdentifier
     * instead of direct reference.
     */
    @org.junit.Test
    public void testSAMLSignedKeyHolderKeyIdentifier() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        
        SAMLIssuer saml = SAMLIssuerFactory.getInstance("saml4.properties");
        // Provide info to SAML issuer that it can construct a Holder-of-key
        // SAML token.
        saml.setInstanceDoc(doc);
        saml.setUserCrypto(crypto);
        saml.setUsername("16c73ab6-b892-458f-abf5-2f875f74882e");
        SAMLAssertion assertion = saml.newAssertion();

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
        SAMLAssertion receivedAssertion = 
            (SAMLAssertion) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
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
        assertTrue(outputString.indexOf("LogTestService2") > 0 ? true : false);
        return results;
    }

}
