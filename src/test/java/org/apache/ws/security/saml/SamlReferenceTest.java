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
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.common.KeystoreCallbackHandler;
import org.apache.ws.security.common.SAML1CallbackHandler;
import org.apache.ws.security.common.SAML2CallbackHandler;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.components.crypto.Merlin;
import org.apache.ws.security.message.WSSecEncrypt;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.apache.ws.security.saml.ext.SAMLParms;
import org.apache.ws.security.saml.ext.builder.SAML1Constants;
import org.apache.ws.security.saml.ext.builder.SAML2Constants;
import org.apache.ws.security.util.Loader;
import org.apache.ws.security.util.WSSecurityUtil;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.io.InputStream;
import java.security.KeyStore;
import java.util.List;
import java.util.ArrayList;

import javax.security.auth.callback.CallbackHandler;

/**
 * Some tests for how SAML tokens are referenced.
 */
public class SamlReferenceTest extends org.junit.Assert {
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(SamlReferenceTest.class);
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private CallbackHandler callbackHandler = new KeystoreCallbackHandler();
    private Crypto crypto = CryptoFactory.getInstance("crypto.properties");
    private Crypto trustCrypto = null;
    private Crypto issuerCrypto = null;
    private Crypto userCrypto = CryptoFactory.getInstance("wss40.properties");
    
    public SamlReferenceTest() throws Exception {
        WSSConfig.init();
        // Load the issuer keystore
        issuerCrypto = new Merlin();
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        ClassLoader loader = Loader.getClassLoader(SignedSamlTokenHOKTest.class);
        InputStream input = Merlin.loadInputStream(loader, "keys/wss40_server.jks");
        keyStore.load(input, "security".toCharArray());
        ((Merlin)issuerCrypto).setKeyStore(keyStore);
        
        // Load the server truststore
        trustCrypto = new Merlin();
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        input = Merlin.loadInputStream(loader, "keys/wss40CA.jks");
        trustStore.load(input, "security".toCharArray());
        ((Merlin)trustCrypto).setTrustStore(trustStore);
    }
    
    /**
     * Test that creates, sends and processes an signed SAML 1.1 sender-vouches assertion,
     * where the SecurityTokenReference that points to the SAML Assertion uses a KeyIdentifier,
     * and not a direct reference.
     */
    @org.junit.Test
    @SuppressWarnings("unchecked")
    public void testSAML1SVKeyIdentifier() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML1Constants.CONF_SENDER_VOUCHES);
        callbackHandler.setIssuer("www.example.com");
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        WSSecSignatureSAML wsSign = new WSSecSignatureSAML();
        wsSign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        Document signedDoc = 
            wsSign.build(
                doc, null, assertion, crypto, "16c73ab6-b892-458f-abf5-2f875f74882e", 
                "security", secHeader
            );

        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed SAML message Key Identifier (sender vouches):");
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains(WSConstants.WSS_SAML_KI_VALUE_TYPE));
        assertTrue(outputString.contains(WSConstants.WSS_SAML_TOKEN_TYPE));
        
        List<WSSecurityEngineResult> results = verify(signedDoc, crypto, null);
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
     * Test that creates, sends and processes an signed SAML 1.1 sender-vouches assertion,
     * where the SecurityTokenReference that points to the SAML Assertion uses a direct reference,
     * and not a KeyIdentifier. This method is not spec compliant and is included to make sure
     * we can process third-party Assertions referenced in this way.
     */
    @org.junit.Test
    @SuppressWarnings("unchecked")
    public void testSAML1SVDirectReference() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML1Constants.CONF_SENDER_VOUCHES);
        callbackHandler.setIssuer("www.example.com");
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        WSSecSignatureSAML wsSign = new WSSecSignatureSAML();
        wsSign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        wsSign.setUseDirectReferenceToAssertion(true);
        Document signedDoc = 
            wsSign.build(
                doc, null, assertion, crypto, "16c73ab6-b892-458f-abf5-2f875f74882e", 
                "security", secHeader
            );

        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed SAML message Direct Reference (sender vouches):");
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains(WSConstants.WSS_SAML_KI_VALUE_TYPE));
        assertTrue(outputString.contains(WSConstants.WSS_SAML_TOKEN_TYPE));
        
        List<WSSecurityEngineResult> results = verify(signedDoc, crypto, null);
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
     * Test that creates, sends and processes an signed SAML 1.1 holder-of-key assertion,
     * where the SecurityTokenReference that points to the SAML Assertion uses a KeyIdentifier,
     * and not a direct reference. This tests that we can process a KeyIdentifier to a SAML
     * Assertion in the KeyInfo of a Signature.
     */
    @org.junit.Test
    @SuppressWarnings("unchecked")
    public void testSAML1HOKKeyIdentifier() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML1Constants.CONF_HOLDER_KEY);
        callbackHandler.setIssuer("www.example.com");
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);
        assertion.signAssertion("wss40_server", "security", issuerCrypto, false);

        WSSecSignatureSAML wsSign = new WSSecSignatureSAML();
        wsSign.setUserInfo("wss40", "security");
        wsSign.setDigestAlgo("http://www.w3.org/2001/04/xmlenc#sha256");
        wsSign.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        Document signedDoc = 
            wsSign.build(doc, userCrypto, assertion, null, null, null, secHeader);

        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed SAML message Key Identifier (holder-of-key):");
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains(WSConstants.WSS_SAML_KI_VALUE_TYPE));
        assertTrue(outputString.contains(WSConstants.WSS_SAML_TOKEN_TYPE));
        
        List<WSSecurityEngineResult> results = verify(signedDoc, trustCrypto, null);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_SIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
        assertTrue(receivedAssertion.isSigned());
        
        // Test we processed a signature (SOAP body)
        actionResult = WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN);
        assertTrue(actionResult != null);
        assertFalse(actionResult.isEmpty());
        final List<WSDataRef> refs =
            (List<WSDataRef>) actionResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
        assertTrue(refs.size() == 1);
        
        WSDataRef wsDataRef = (WSDataRef)refs.get(0);
        String xpath = wsDataRef.getXpath();
        assertEquals("/SOAP-ENV:Envelope/SOAP-ENV:Body", xpath);
    }
    
    /**
     * Test that creates, sends and processes an signed SAML 1.1 holder-of-key assertion,
     * where the SecurityTokenReference that points to the SAML Assertion uses a direct reference,
     * and not a KeyIdentifier. This method is not spec compliant and is included to make sure
     * we can process third-party Assertions referenced in this way. This tests that we can 
     * process a Direct Reference to a SAML Assertion in the KeyInfo of a Signature.
     */
    @org.junit.Test
    @SuppressWarnings("unchecked")
    public void testSAML1HOKDirectReference() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML1Constants.CONF_HOLDER_KEY);
        callbackHandler.setIssuer("www.example.com");
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);
        assertion.signAssertion("wss40_server", "security", issuerCrypto, false);

        WSSecSignatureSAML wsSign = new WSSecSignatureSAML();
        wsSign.setUserInfo("wss40", "security");
        wsSign.setDigestAlgo("http://www.w3.org/2001/04/xmlenc#sha256");
        wsSign.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        wsSign.setUseDirectReferenceToAssertion(true);
        wsSign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        Document signedDoc = 
            wsSign.build(doc, userCrypto, assertion, null, null, null, secHeader);

        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed SAML message Direct Reference (holder-of-key):");
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains(WSConstants.WSS_SAML_KI_VALUE_TYPE));
        assertTrue(outputString.contains(WSConstants.WSS_SAML_TOKEN_TYPE));
        
        List<WSSecurityEngineResult> results = verify(signedDoc, trustCrypto, null);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_SIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
        assertTrue(receivedAssertion.isSigned());
        
        // Test we processed a signature (SOAP body)
        actionResult = WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN);
        assertTrue(actionResult != null);
        assertFalse(actionResult.isEmpty());
        final List<WSDataRef> refs =
            (List<WSDataRef>) actionResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
        assertTrue(refs.size() == 1);
        
        WSDataRef wsDataRef = (WSDataRef)refs.get(0);
        String xpath = wsDataRef.getXpath();
        assertEquals("/SOAP-ENV:Envelope/SOAP-ENV:Body", xpath);
    }

    /**
     * WS-Security Test Case for WSS-178 - "signature verification failure of signed saml token
     * due to "The Reference for URI (bst-saml-uri) has no XMLSignatureInput".
     * 
     * The problem is that the signature is referring to a SecurityTokenReference via the 
     * STRTransform, which in turn is referring to the SAML Assertion. The request is putting 
     * the SAML Assertion below the SecurityTokenReference, and this is causing 
     * SecurityTokenReference.getTokenElement to fail.
     */
    @org.junit.Test
    public void testAssertionBelowSTR() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        SAMLIssuer saml = SAMLIssuerFactory.getInstance("saml_sv.properties");
        AssertionWrapper assertion = saml.newAssertion();
        Crypto crypto = CryptoFactory.getInstance("crypto.properties");
        WSSecSignatureSAML wsSign = new WSSecSignatureSAML();
        wsSign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        Document samlDoc = 
            wsSign.build(doc, null, assertion, crypto, 
                "16c73ab6-b892-458f-abf5-2f875f74882e", "security", secHeader
            );
        
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        Document encryptedDoc = builder.build(samlDoc, crypto, secHeader);
        
        //
        // Remove the assertion its place in the security header and then append it
        //
        org.w3c.dom.Element secHeaderElement = secHeader.getSecurityHeader();
        org.w3c.dom.Node assertionNode = 
            secHeaderElement.getElementsByTagNameNS(WSConstants.SAML_NS, "Assertion").item(0);
        secHeaderElement.removeChild(assertionNode);
        secHeaderElement.appendChild(assertionNode);

        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(encryptedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Encrypted message:");
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains(WSConstants.WSS_SAML_KI_VALUE_TYPE));
        assertTrue(outputString.contains(WSConstants.WSS_SAML_TOKEN_TYPE));
        
        verify(encryptedDoc, crypto, crypto);
    }
    
    
    /**
     * The body of the SOAP request is encrypted using a secret key, which is in turn encrypted
     * using the certificate embedded in the SAML assertion and referenced using a Key Identifier.
     * This tests that we can process a KeyIdentifier to a SAML Assertion in the KeyInfo of an
     * EncryptedKey.
     */
    @org.junit.Test
    @SuppressWarnings("unchecked")
    public void testSAML1HOKEKKeyIdentifier() throws Exception {
        // Create a SAML assertion
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML1Constants.CONF_HOLDER_KEY);
        callbackHandler.setIssuer("www.example.com");
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);
        assertion.signAssertion("wss40_server", "security", issuerCrypto, false);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        Node assertionNode = assertion.toDOM(doc);
        secHeader.insertSecurityHeader(doc);
        secHeader.getSecurityHeader().appendChild(assertionNode);
        
        // Encrypt the SOAP body
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setUserInfo("wss40");
        builder.setSymmetricEncAlgorithm(WSConstants.TRIPLE_DES);
        builder.setKeyIdentifierType(WSConstants.CUSTOM_KEY_IDENTIFIER);
        builder.setCustomEKTokenValueType(WSConstants.WSS_SAML_KI_VALUE_TYPE);
        builder.setCustomEKTokenId(assertion.getId());
        builder.prepare(doc, userCrypto);
        
        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        WSEncryptionPart encP = 
            new WSEncryptionPart(
                "add", "http://ws.apache.org/counter/counter_port_type", "Element"
            );
        parts.add(encP);
        Element refElement = builder.encryptForRef(null, parts);
        builder.addInternalRefElement(refElement);
        builder.appendToHeader(secHeader);

        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Encrypted SAML 1.1 message Key Identifier (holder-of-key):");
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains(WSConstants.WSS_SAML_KI_VALUE_TYPE));
        assertTrue(outputString.contains(WSConstants.WSS_SAML_TOKEN_TYPE));
        
        List<WSSecurityEngineResult> results = verify(doc, trustCrypto, userCrypto);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_SIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
        assertTrue(receivedAssertion.isSigned());
        
        // Test we processed an encrypted element
        actionResult = WSSecurityUtil.fetchActionResult(results, WSConstants.ENCR);
        assertTrue(actionResult != null);
        assertFalse(actionResult.isEmpty());
        final List<WSDataRef> refs =
            (List<WSDataRef>) actionResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
        assertTrue(refs.size() == 1);
        
        WSDataRef wsDataRef = (WSDataRef)refs.get(0);
        String xpath = wsDataRef.getXpath();
        assertEquals("/SOAP-ENV:Envelope/SOAP-ENV:Body/add", xpath);
        
    }
    
    /**
     * The body of the SOAP request is encrypted using a secret key, which is in turn encrypted
     * using the certificate embedded in the SAML assertion and referenced using Direct
     * Reference. This method is not spec compliant and is included to make sure we can process 
     * third-party Assertions referenced in this way. This tests that we can process a Direct
     * Reference to a SAML Assertion in the KeyInfo of an EncryptedKey.
     */
    @org.junit.Test
    @SuppressWarnings("unchecked")
    public void testSAML1HOKEKDirectReference() throws Exception {
        // Create a SAML assertion
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML1Constants.CONF_HOLDER_KEY);
        callbackHandler.setIssuer("www.example.com");
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);
        assertion.signAssertion("wss40_server", "security", issuerCrypto, false);
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        Node assertionNode = assertion.toDOM(doc);
        secHeader.insertSecurityHeader(doc);
        secHeader.getSecurityHeader().appendChild(assertionNode);
        
        // Encrypt the SOAP body
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setUserInfo("wss40");
        builder.setSymmetricEncAlgorithm(WSConstants.TRIPLE_DES);
        builder.setKeyIdentifierType(WSConstants.CUSTOM_SYMM_SIGNING);
        builder.setCustomEKTokenValueType(WSConstants.WSS_SAML_KI_VALUE_TYPE);
        builder.setCustomEKTokenId(assertion.getId());
        builder.prepare(doc, userCrypto);
        
        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        WSEncryptionPart encP = 
            new WSEncryptionPart(
                "add", "http://ws.apache.org/counter/counter_port_type", "Element"
            );
        parts.add(encP);
        Element refElement = builder.encryptForRef(null, parts);
        builder.addInternalRefElement(refElement);
        builder.appendToHeader(secHeader);

        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Encrypted SAML 1.1 message Direct Reference (holder-of-key):");
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains(WSConstants.WSS_SAML_KI_VALUE_TYPE));
        assertTrue(outputString.contains(WSConstants.WSS_SAML_TOKEN_TYPE));
        
        List<WSSecurityEngineResult> results = verify(doc, trustCrypto, userCrypto);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_SIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
        assertTrue(receivedAssertion.isSigned());
        
        // Test we processed an encrypted element
        actionResult = WSSecurityUtil.fetchActionResult(results, WSConstants.ENCR);
        assertTrue(actionResult != null);
        assertFalse(actionResult.isEmpty());
        final List<WSDataRef> refs =
            (List<WSDataRef>) actionResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
        assertTrue(refs.size() == 1);
        
        WSDataRef wsDataRef = (WSDataRef)refs.get(0);
        String xpath = wsDataRef.getXpath();
        assertEquals("/SOAP-ENV:Envelope/SOAP-ENV:Body/add", xpath);
    }
    
    /**
     * Test that creates, sends and processes an signed SAML 2 sender-vouches assertion,
     * where the SecurityTokenReference that points to the SAML Assertion uses a KeyIdentifier,
     * and not a direct reference.
     */
    @org.junit.Test
    @SuppressWarnings("unchecked")
    public void testSAML2SVKeyIdentifier() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_SENDER_VOUCHES);
        callbackHandler.setIssuer("www.example.com");
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        WSSecSignatureSAML wsSign = new WSSecSignatureSAML();
        wsSign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        Document signedDoc = 
            wsSign.build(
                doc, null, assertion, crypto, "16c73ab6-b892-458f-abf5-2f875f74882e", 
                "security", secHeader
            );

        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed SAML2 message Key Identifier (sender vouches):");
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains(WSConstants.WSS_SAML2_KI_VALUE_TYPE));
        assertTrue(outputString.contains(WSConstants.WSS_SAML2_TOKEN_TYPE));
        
        List<WSSecurityEngineResult> results = verify(signedDoc, crypto, null);
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
     * Test that creates, sends and processes an signed SAML 2 sender-vouches assertion,
     * where the SecurityTokenReference that points to the SAML Assertion uses a direct reference,
     * and not a KeyIdentifier. Unlike the SAML 1.1 case, this is spec-compliant.
     */
    @org.junit.Test
    @SuppressWarnings("unchecked")
    public void testSAML2SVDirectReference() throws Exception {
    	SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_SENDER_VOUCHES);
        callbackHandler.setIssuer("www.example.com");
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        WSSecSignatureSAML wsSign = new WSSecSignatureSAML();
        wsSign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        wsSign.setUseDirectReferenceToAssertion(true);
        Document signedDoc = 
            wsSign.build(
                doc, null, assertion, crypto, "16c73ab6-b892-458f-abf5-2f875f74882e", 
                "security", secHeader
            );

        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed SAML2 message Direct Reference (sender vouches):");
            LOG.debug(outputString);
        }
        assertTrue(!outputString.contains(WSConstants.WSS_SAML2_KI_VALUE_TYPE));
        assertTrue(outputString.contains(WSConstants.WSS_SAML2_TOKEN_TYPE));
        
        List<WSSecurityEngineResult> results = verify(signedDoc, crypto, null);
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
     * Test that creates, sends and processes an signed SAML 2 holder-of-key assertion,
     * where the SecurityTokenReference that points to the SAML Assertion uses a KeyIdentifier,
     * and not a direct reference. This tests that we can process a KeyIdentifier to a SAML
     * Assertion in the KeyInfo of a Signature.
     */
    @org.junit.Test
    @SuppressWarnings("unchecked")
    public void testSAML2HOKKeyIdentifier() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_HOLDER_KEY);
        callbackHandler.setIssuer("www.example.com");
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);
        assertion.signAssertion("wss40_server", "security", issuerCrypto, false);

        WSSecSignatureSAML wsSign = new WSSecSignatureSAML();
        wsSign.setUserInfo("wss40", "security");
        wsSign.setDigestAlgo("http://www.w3.org/2001/04/xmlenc#sha256");
        wsSign.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        Document signedDoc = 
            wsSign.build(doc, userCrypto, assertion, null, null, null, secHeader);

        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed SAML2 message Key Identifier (holder-of-key):");
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains(WSConstants.WSS_SAML2_KI_VALUE_TYPE));
        assertTrue(outputString.contains(WSConstants.WSS_SAML2_TOKEN_TYPE));
        
        List<WSSecurityEngineResult> results = verify(signedDoc, trustCrypto, null);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_SIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
        assertTrue(receivedAssertion.isSigned());
        
        // Test we processed a signature (SOAP body)
        actionResult = WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN);
        assertTrue(actionResult != null);
        assertFalse(actionResult.isEmpty());
        final List<WSDataRef> refs =
            (List<WSDataRef>) actionResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
        assertTrue(refs.size() == 1);
        
        WSDataRef wsDataRef = (WSDataRef)refs.get(0);
        String xpath = wsDataRef.getXpath();
        assertEquals("/SOAP-ENV:Envelope/SOAP-ENV:Body", xpath);
    }
    
    
    /**
     * Test that creates, sends and processes an signed SAML 2 holder-of-key assertion,
     * where the SecurityTokenReference that points to the SAML Assertion uses a direct reference,
     * and not a KeyIdentifier. Unlike the SAML 1.1 case, this is spec-compliant. This tests that
     * we can process a Direct Reference to a SAML Assertion in the KeyInfo of a Signature.
     */
    @org.junit.Test
    @SuppressWarnings("unchecked")
    public void testSAML2HOKDirectReference() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_HOLDER_KEY);
        callbackHandler.setIssuer("www.example.com");
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);
        assertion.signAssertion("wss40_server", "security", issuerCrypto, false);

        WSSecSignatureSAML wsSign = new WSSecSignatureSAML();
        wsSign.setUserInfo("wss40", "security");
        wsSign.setDigestAlgo("http://www.w3.org/2001/04/xmlenc#sha256");
        wsSign.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        wsSign.setUseDirectReferenceToAssertion(true);
        wsSign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        Document signedDoc = 
            wsSign.build(doc, userCrypto, assertion, null, null, null, secHeader);

        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed SAML2 message Direct Reference (holder-of-key):");
            LOG.debug(outputString);
        }
        assertTrue(!outputString.contains(WSConstants.WSS_SAML2_KI_VALUE_TYPE));
        assertTrue(outputString.contains(WSConstants.WSS_SAML2_TOKEN_TYPE));
        
        List<WSSecurityEngineResult> results = verify(signedDoc, trustCrypto, null);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_SIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
        assertTrue(receivedAssertion.isSigned());
        
        // Test we processed a signature (SOAP body)
        actionResult = WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN);
        assertTrue(actionResult != null);
        assertFalse(actionResult.isEmpty());
        final List<WSDataRef> refs =
            (List<WSDataRef>) actionResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
        assertTrue(refs.size() == 1);
        
        WSDataRef wsDataRef = (WSDataRef)refs.get(0);
        String xpath = wsDataRef.getXpath();
        assertEquals("/SOAP-ENV:Envelope/SOAP-ENV:Body", xpath);
    }
    
    /**
     * The body of the SOAP request is encrypted using a secret key, which is in turn encrypted
     * using the certificate embedded in the SAML assertion and referenced using a Key Identifier.
     * This tests that we can process a KeyIdentifier to a SAML Assertion in the KeyInfo of an
     * EncryptedKey.
     */
    @org.junit.Test
    @SuppressWarnings("unchecked")
    public void testSAML2HOKEKKeyIdentifier() throws Exception {
        // Create a SAML assertion
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_HOLDER_KEY);
        callbackHandler.setIssuer("www.example.com");
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);
        assertion.signAssertion("wss40_server", "security", issuerCrypto, false);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        Node assertionNode = assertion.toDOM(doc);
        secHeader.insertSecurityHeader(doc);
        secHeader.getSecurityHeader().appendChild(assertionNode);
        
        // Encrypt the SOAP body
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setUserInfo("wss40");
        builder.setSymmetricEncAlgorithm(WSConstants.TRIPLE_DES);
        builder.setKeyIdentifierType(WSConstants.CUSTOM_KEY_IDENTIFIER);
        builder.setCustomEKTokenValueType(WSConstants.WSS_SAML2_KI_VALUE_TYPE);
        builder.setCustomEKTokenId(assertion.getId());
        builder.prepare(doc, userCrypto);
        
        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        WSEncryptionPart encP = 
            new WSEncryptionPart(
                "add", "http://ws.apache.org/counter/counter_port_type", "Element"
            );
        parts.add(encP);
        Element refElement = builder.encryptForRef(null, parts);
        builder.addInternalRefElement(refElement);
        builder.appendToHeader(secHeader);

        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Encrypted SAML 2 message Key Identifier (holder-of-key):");
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains(WSConstants.WSS_SAML2_KI_VALUE_TYPE));
        assertTrue(outputString.contains(WSConstants.WSS_SAML2_TOKEN_TYPE));
        
        List<WSSecurityEngineResult> results = verify(doc, trustCrypto, userCrypto);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_SIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
        assertTrue(receivedAssertion.isSigned());
        
        // Test we processed an encrypted element
        actionResult = WSSecurityUtil.fetchActionResult(results, WSConstants.ENCR);
        assertTrue(actionResult != null);
        assertFalse(actionResult.isEmpty());
        final List<WSDataRef> refs =
            (List<WSDataRef>) actionResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
        assertTrue(refs.size() == 1);
        
        WSDataRef wsDataRef = (WSDataRef)refs.get(0);
        String xpath = wsDataRef.getXpath();
        assertEquals("/SOAP-ENV:Envelope/SOAP-ENV:Body/add", xpath);
        
    }
    
    /**
     * The body of the SOAP request is encrypted using a secret key, which is in turn encrypted
     * using the certificate embedded in the SAML assertion and referenced using Direct
     * Reference. Unlike the SAML 1.1 case, this is spec-compliant. This tests that we can process
     * a Direct Reference to a SAML Assertion in the KeyInfo of an EncryptedKey.
     */
    @org.junit.Test
    @SuppressWarnings("unchecked")
    public void testSAML2HOKEKDirectReference() throws Exception {
        // Create a SAML assertion
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_HOLDER_KEY);
        callbackHandler.setIssuer("www.example.com");
        
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = new AssertionWrapper(samlParms);
        assertion.signAssertion("wss40_server", "security", issuerCrypto, false);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        Node assertionNode = assertion.toDOM(doc);
        secHeader.insertSecurityHeader(doc);
        secHeader.getSecurityHeader().appendChild(assertionNode);
        
        // Encrypt the SOAP body
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setUserInfo("wss40");
        builder.setSymmetricEncAlgorithm(WSConstants.TRIPLE_DES);
        builder.setKeyIdentifierType(WSConstants.CUSTOM_SYMM_SIGNING);
        builder.setCustomEKTokenValueType(WSConstants.WSS_SAML2_KI_VALUE_TYPE);
        builder.setCustomEKTokenId(assertion.getId());
        builder.prepare(doc, userCrypto);
        
        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        WSEncryptionPart encP = 
            new WSEncryptionPart(
                "add", "http://ws.apache.org/counter/counter_port_type", "Element"
            );
        parts.add(encP);
        Element refElement = builder.encryptForRef(null, parts);
        builder.addInternalRefElement(refElement);
        builder.appendToHeader(secHeader);

        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Encrypted SAML 2 message Direct Reference (holder-of-key):");
            LOG.debug(outputString);
        }
        assertTrue(!outputString.contains(WSConstants.WSS_SAML2_KI_VALUE_TYPE));
        assertTrue(outputString.contains(WSConstants.WSS_SAML2_TOKEN_TYPE));
        
        List<WSSecurityEngineResult> results = verify(doc, trustCrypto, userCrypto);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_SIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
        assertTrue(receivedAssertion.isSigned());
        
        // Test we processed an encrypted element
        actionResult = WSSecurityUtil.fetchActionResult(results, WSConstants.ENCR);
        assertTrue(actionResult != null);
        assertFalse(actionResult.isEmpty());
        final List<WSDataRef> refs =
            (List<WSDataRef>) actionResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
        assertTrue(refs.size() == 1);
        
        WSDataRef wsDataRef = (WSDataRef)refs.get(0);
        String xpath = wsDataRef.getXpath();
        assertEquals("/SOAP-ENV:Envelope/SOAP-ENV:Body/add", xpath);
        
    }
    
    
    /**
     * Verifies the soap envelope
     * 
     * @param doc
     * @throws Exception Thrown when there is a problem in verification
     */
    private List<WSSecurityEngineResult> verify(
        Document doc, Crypto verifyCrypto, Crypto decCrypto
    ) throws Exception {
        List<WSSecurityEngineResult> results = 
            secEngine.processSecurityHeader(doc, null, callbackHandler, verifyCrypto, decCrypto);
        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
        assertTrue(outputString.indexOf("counter_port_type") > 0 ? true : false);
        return results;
    }
    
}
