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

import org.apache.ws.security.saml.SAMLIssuer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.common.KeystoreCallbackHandler;
import org.apache.ws.security.common.SAML1CallbackHandler;
import org.apache.ws.security.common.SAML2CallbackHandler;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.components.crypto.AbstractCrypto;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.components.crypto.Merlin;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.WSSecSAMLToken;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.apache.ws.security.saml.ext.builder.SAML1Constants;
import org.apache.ws.security.saml.ext.builder.SAML2Constants;
import org.apache.ws.security.util.Loader;
import org.w3c.dom.Document;

import javax.security.auth.callback.CallbackHandler;

import java.io.InputStream;
import java.security.KeyStore;
import java.util.List;

import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * This is a set of test-cases where the SAML Assertion is altered in some way and so
 * we expect an exception to be thrown when processing it.
 */
public class SamlNegativeTest extends org.junit.Assert {
    private static final Log LOG = LogFactory.getLog(SamlNegativeTest.class);
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private CallbackHandler callbackHandler = new KeystoreCallbackHandler();
    private Crypto trustCrypto = null;
    private Crypto issuerCrypto = null;
    private Crypto userCrypto = CryptoFactory.getInstance("wss40.properties");
    
    public SamlNegativeTest() throws Exception {
        // Load the issuer keystore
        issuerCrypto = new Merlin();
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        ClassLoader loader = Loader.getClassLoader(SamlNegativeTest.class);
        InputStream input = AbstractCrypto.loadInputStream(loader, "keys/wss40_server.jks");
        keyStore.load(input, "security".toCharArray());
        issuerCrypto.setKeyStore(keyStore);
        
        // Load the server truststore
        trustCrypto = new Merlin();
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        input = AbstractCrypto.loadInputStream(loader, "keys/wss40CA.jks");
        trustStore.load(input, "security".toCharArray());
        trustCrypto.setTrustStore(trustStore);
    }
    
    /**
     * Test that creates, sends and processes a signed SAML 2 sender-vouches
     * authentication assertion. The assertion is altered and so the signature validation
     * should fail.
     */
    @org.junit.Test
    public void testSAML2AuthnAssertionModified() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_SENDER_VOUCHES);
        SAMLIssuer saml = new SAMLIssuerImpl();
        saml.setSamlVersion("2.0");
        saml.setIssuerName("www.example.com");
        saml.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = saml.newAssertion();

        WSSecSignatureSAML wsSign = new WSSecSignatureSAML();
        wsSign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document signedDoc = 
            wsSign.build(
                doc, null, assertion, userCrypto, "wss40", "security", secHeader
            );
        
        //
        // Modify the assertion
        //
        Element envelope = signedDoc.getDocumentElement();
        NodeList list = envelope.getElementsByTagNameNS(WSConstants.SAML2_NS, "Assertion");
        Element assertionElement = (org.w3c.dom.Element)list.item(0);
        assertionElement.setAttributeNS(null, "MinorVersion", "5");

        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 2 Authn Assertion (sender vouches):");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        try {
            verify(signedDoc, trustCrypto);
            fail("Failure expected on a modified SAML Assertion");
        } catch (Exception ex) {
            // expected
        }
    }
    
    /**
     * Test that creates a signed SAML 1.1 Assertion using HOK, but then modifies the signature
     * object by replacing the enveloped transform with the exclusive c14n transform. 
     * The signature validation should then fail - the enveloped transform is mandatory for
     * a signed assertion.
     */
    @org.junit.Test
    public void testSAML1SignedKeyHolderSigModified() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML1Constants.CONF_HOLDER_KEY);
        SAMLIssuer saml = new SAMLIssuerImpl();
        saml.setIssuerName("www.example.com");
        saml.setIssuerCrypto(issuerCrypto);
        saml.setIssuerKeyName("wss40_server");
        saml.setIssuerKeyPassword("security");
        saml.setSignAssertion(true);
        saml.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = saml.newAssertion();

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document signedDoc = wsSign.build(doc, assertion, secHeader);

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
            verify(signedDoc, trustCrypto);
            fail("Expected failure on a modified signature");
        } catch (WSSecurityException ex) {
            // expected
        }
    }
    
    /**
     * Test that creates a signed SAML 2 Assertion using HOK, but then modifies the assertion.
     * The signature verification should then fail.
     */
    @org.junit.Test
    public void testSAML2SignedKeyHolderKeyModified() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_HOLDER_KEY);
        SAMLIssuer saml = new SAMLIssuerImpl();
        saml.setIssuerName("www.example.com");
        saml.setIssuerCrypto(issuerCrypto);
        saml.setIssuerKeyName("wss40_server");
        saml.setIssuerKeyPassword("security");
        saml.setSignAssertion(true);
        saml.setSamlVersion("2.0");
        saml.setCallbackHandler(callbackHandler);
        AssertionWrapper assertion = saml.newAssertion();

        WSSecSAMLToken wsSign = new WSSecSAMLToken();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document signedDoc = wsSign.build(doc, assertion, secHeader);
        //
        // Modify the assertion
        //
        Element envelope = signedDoc.getDocumentElement();
        NodeList list = envelope.getElementsByTagNameNS(WSConstants.SAML2_NS, "Assertion");
        Element assertionElement = (org.w3c.dom.Element)list.item(0);
        assertionElement.setAttributeNS(null, "MinorVersion", "5");
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed (modified) SAML message (key holder):");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        try {
            verify(signedDoc, trustCrypto);
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
    private List<WSSecurityEngineResult> verify(Document doc, Crypto sigCrypto) throws Exception {
        List<WSSecurityEngineResult> results = 
            secEngine.processSecurityHeader(
                doc, null, callbackHandler, sigCrypto, userCrypto
            );
        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
        assertTrue(outputString.indexOf("counter_port_type") > 0 ? true : false);
        return results;
    }

}
