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

package org.apache.wss4j.dom.saml;

import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSDataRef;
import org.apache.wss4j.dom.common.KeystoreCallbackHandler;
import org.apache.wss4j.dom.common.SAML1CallbackHandler;
import org.apache.wss4j.dom.common.SAML2CallbackHandler;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.crypto.Merlin;
import org.apache.wss4j.common.saml.SAMLCallback;
import org.apache.wss4j.common.saml.SAMLUtil;
import org.apache.wss4j.common.saml.bean.KeyInfoBean.CERT_IDENTIFIER;
import org.apache.wss4j.common.saml.builder.SAML1Constants;
import org.apache.wss4j.common.saml.builder.SAML2Constants;
import org.apache.wss4j.common.util.Loader;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.security.auth.callback.CallbackHandler;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Test-case for sending and processing a signed (holder-of-key) SAML Assertion. These tests
 * also cover the case of using the credential information in the SAML Subject to sign the
 * SOAP body.
 */
public class SignedSamlTokenHOKTest extends org.junit.Assert {
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(SignedSamlTokenHOKTest.class);
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private CallbackHandler callbackHandler = new KeystoreCallbackHandler();
    private Crypto trustCrypto = null;
    private Crypto issuerCrypto = null;
    private Crypto userCrypto = CryptoFactory.getInstance("wss40.properties");

    @org.junit.AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }

    public SignedSamlTokenHOKTest() throws Exception {
        WSSConfig.init();
        // Load the issuer keystore
        issuerCrypto = new Merlin();
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        ClassLoader loader = Loader.getClassLoader(SignedSamlTokenHOKTest.class);
        InputStream input = Merlin.loadInputStream(loader, "keys/wss40_server.jks");
        keyStore.load(input, "security".toCharArray());
        input.close();
        ((Merlin)issuerCrypto).setKeyStore(keyStore);

        // Load the server truststore
        trustCrypto = new Merlin();
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        input = Merlin.loadInputStream(loader, "keys/wss40CA.jks");
        trustStore.load(input, "security".toCharArray());
        input.close();
        ((Merlin)trustCrypto).setTrustStore(trustStore);
    }

    /**
     * Test that creates, sends and processes a signed SAML 1.1 authentication assertion.
     */
    @Test
    @SuppressWarnings("unchecked")
    public void testSAML1AuthnAssertion() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML1Constants.CONF_HOLDER_KEY);
        callbackHandler.setIssuer("www.example.com");

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        samlAssertion.signAssertion("wss40_server", "security", issuerCrypto, false);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        
        WSSecSignatureSAML wsSign = new WSSecSignatureSAML(secHeader);
        wsSign.setUserInfo("wss40", "security");
        wsSign.setDigestAlgo("http://www.w3.org/2001/04/xmlenc#sha256");
        wsSign.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        wsSign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);

        Document signedDoc =
            wsSign.build(userCrypto, samlAssertion, null, null, null);

        String outputString =
            XMLUtils.prettyDocumentToString(signedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed SAML 1.1 Authn Assertion (key holder):");
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains("http://www.w3.org/2001/04/xmlenc#sha256"));
        assertTrue(outputString.contains("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"));

        WSHandlerResult results = verify(signedDoc, trustCrypto);

        // Test we processed a SAML assertion
        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.ST_SIGNED).get(0);
        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertTrue(receivedSamlAssertion.isSigned());
        assertTrue(receivedSamlAssertion.getSignatureValue() != null);

        // Test we have a WSDataRef for the signed SAML token as well
        List<WSDataRef> refs =
            (List<WSDataRef>) actionResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
        assertTrue(refs.size() == 1);

        WSDataRef wsDataRef = refs.get(0);
        String xpath = wsDataRef.getXpath();
        assertEquals("/SOAP-ENV:Envelope/SOAP-ENV:Header/wsse:Security/saml1:Assertion", xpath);

        // Test we processed a signature (SOAP body)
        actionResult = results.getActionResults().get(WSConstants.SIGN).get(0);
        assertTrue(actionResult != null);
        assertFalse(actionResult.isEmpty());
        refs = (List<WSDataRef>) actionResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
        assertTrue(refs.size() == 1);

        wsDataRef = refs.get(0);
        xpath = wsDataRef.getXpath();
        assertEquals("/SOAP-ENV:Envelope/SOAP-ENV:Body", xpath);
    }

    /**
     * Test that creates, sends and processes a signed SAML 1.1 attribute assertion.
     */
    @Test
    public void testSAML1AttrAssertion() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML1Constants.CONF_HOLDER_KEY);
        callbackHandler.setIssuer("www.example.com");

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        samlAssertion.signAssertion("wss40_server", "security", issuerCrypto, false);
        byte[] ephemeralKey = callbackHandler.getEphemeralKey();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        
        WSSecSignatureSAML wsSign = new WSSecSignatureSAML(secHeader);
        wsSign.setUserInfo("wss40", "security");
        wsSign.setDigestAlgo("http://www.w3.org/2001/04/xmlenc#sha256");
        wsSign.setSignatureAlgorithm(WSConstants.HMAC_SHA256);
        wsSign.setKeyIdentifierType(WSConstants.X509_KEY_IDENTIFIER);
        wsSign.setSecretKey(ephemeralKey);

        Document signedDoc =
            wsSign.build(userCrypto, samlAssertion, null, null, null);

        String outputString =
            XMLUtils.prettyDocumentToString(signedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed SAML 1.1 Attr Assertion (key holder):");
            LOG.debug(outputString);
        }

        /* https://issues.apache.org/jira/browse/WSS-265 */
        WSHandlerResult results = verify(signedDoc, trustCrypto);

        // Test we processed a SAML assertion
        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.ST_SIGNED).get(0);
        SamlAssertionWrapper receivedAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
        assertTrue(receivedAssertion.isSigned());

        // Test we processed a signature (SOAP body)
        actionResult = results.getActionResults().get(WSConstants.SIGN).get(0);
        assertTrue(actionResult != null);
        assertFalse(actionResult.isEmpty());
        @SuppressWarnings("unchecked")
        final List<WSDataRef> refs =
            (List<WSDataRef>) actionResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
        assertTrue(refs.size() == 1);

        WSDataRef wsDataRef = refs.get(0);
        String xpath = wsDataRef.getXpath();
        assertEquals("/SOAP-ENV:Envelope/SOAP-ENV:Body", xpath);
    }

    /**
     * Test that creates, sends and processes a signed SAML 2 authentication assertion.
     */
    @Test
    @SuppressWarnings("unchecked")
    public void testSAML2AuthnAssertion() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_HOLDER_KEY);
        callbackHandler.setIssuer("www.example.com");

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        samlAssertion.signAssertion("wss40_server", "security", issuerCrypto, false);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        
        WSSecSignatureSAML wsSign = new WSSecSignatureSAML(secHeader);
        wsSign.setUserInfo("wss40", "security");
        wsSign.setDigestAlgo("http://www.w3.org/2001/04/xmlenc#sha256");
        wsSign.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        wsSign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);

        Document signedDoc =
            wsSign.build(userCrypto, samlAssertion, null, null, null);

        String outputString =
            XMLUtils.prettyDocumentToString(signedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed SAML 2 Authn Assertion (key holder):");
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains("http://www.w3.org/2001/04/xmlenc#sha256"));
        assertTrue(outputString.contains("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"));

        WSHandlerResult results = verify(signedDoc, trustCrypto);

        // Test we processed a SAML assertion
        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.ST_SIGNED).get(0);
        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertTrue(receivedSamlAssertion.isSigned());

        // Test we processed a signature (SOAP body)
        actionResult = results.getActionResults().get(WSConstants.SIGN).get(0);
        assertTrue(actionResult != null);
        assertFalse(actionResult.isEmpty());
        final List<WSDataRef> refs =
            (List<WSDataRef>) actionResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
        assertTrue(refs.size() == 1);

        WSDataRef wsDataRef = refs.get(0);
        String xpath = wsDataRef.getXpath();
        assertEquals("/SOAP-ENV:Envelope/SOAP-ENV:Body", xpath);
    }

    /**
     * Test that creates, sends and processes a signed SAML 2 attribute assertion.
     */
    @Test
    public void testSAML2AttrAssertion() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_HOLDER_KEY);
        callbackHandler.setIssuer("www.example.com");

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        samlAssertion.signAssertion("wss40_server", "security", issuerCrypto, false);
        byte[] ephemeralKey = callbackHandler.getEphemeralKey();

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        
        WSSecSignatureSAML wsSign = new WSSecSignatureSAML(secHeader);
        wsSign.setUserInfo("wss40", "security");
        wsSign.setDigestAlgo("http://www.w3.org/2001/04/xmlenc#sha256");
        wsSign.setSignatureAlgorithm(WSConstants.HMAC_SHA256);
        wsSign.setKeyIdentifierType(WSConstants.X509_KEY_IDENTIFIER);
        wsSign.setSecretKey(ephemeralKey);

        Document signedDoc =
            wsSign.build(userCrypto, samlAssertion, null, null, null);

        String outputString =
            XMLUtils.prettyDocumentToString(signedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed SAML 2 Attr Assertion (key holder):");
            LOG.debug(outputString);
        }

        /* https://issues.apache.org/jira/browse/WSS-265 */
        WSHandlerResult results = verify(signedDoc, trustCrypto);

        // Test we processed a SAML assertion
        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.ST_SIGNED).get(0);
        SamlAssertionWrapper receivedAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
        assertTrue(receivedAssertion.isSigned());

        // Test we processed a signature (SOAP body)
        actionResult = results.getActionResults().get(WSConstants.SIGN).get(0);
        assertTrue(actionResult != null);
        assertFalse(actionResult.isEmpty());
        @SuppressWarnings("unchecked")
        final List<WSDataRef> refs =
            (List<WSDataRef>) actionResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
        assertTrue(refs.size() == 1);

        WSDataRef wsDataRef = refs.get(0);
        String xpath = wsDataRef.getXpath();
        assertEquals("/SOAP-ENV:Envelope/SOAP-ENV:Body", xpath);
    }

    /**
     * Test that creates, sends and processes a signed SAML 1.1 authentication assertion,
     * where the subject cert is referenced using IssuerSerial
     */
    @Test
    @SuppressWarnings("unchecked")
    public void testSAML1AuthnAssertionIssuerSerial() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML1Constants.CONF_HOLDER_KEY);
        callbackHandler.setCertIdentifier(CERT_IDENTIFIER.X509_ISSUER_SERIAL);
        callbackHandler.setIssuer("www.example.com");

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        samlAssertion.signAssertion("wss40_server", "security", issuerCrypto, false);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        
        WSSecSignatureSAML wsSign = new WSSecSignatureSAML(secHeader);
        wsSign.setUserInfo("wss40", "security");
        wsSign.setDigestAlgo("http://www.w3.org/2001/04/xmlenc#sha256");
        wsSign.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        wsSign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);

        Document signedDoc =
            wsSign.build(userCrypto, samlAssertion, null, null, null);

        String outputString =
            XMLUtils.prettyDocumentToString(signedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 1.1 Authn Assertion Issuer Serial (holder-of-key):");
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains("X509IssuerSerial"));

        WSHandlerResult results = verify(signedDoc, userCrypto);
        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.ST_SIGNED).get(0);
        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertTrue(receivedSamlAssertion.isSigned());

        // Test we processed a signature (SOAP body)
        actionResult = results.getActionResults().get(WSConstants.SIGN).get(0);
        assertTrue(actionResult != null);
        assertFalse(actionResult.isEmpty());
        final List<WSDataRef> refs =
            (List<WSDataRef>) actionResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
        assertTrue(refs.size() == 1);

        WSDataRef wsDataRef = refs.get(0);
        String xpath = wsDataRef.getXpath();
        assertEquals("/SOAP-ENV:Envelope/SOAP-ENV:Body", xpath);
    }

    /**
     * Test that creates, sends and processes a signed SAML 1.1 authentication assertion,
     * where the subject cert is referenced using a Key Value
     */
    @Test
    @SuppressWarnings("unchecked")
    public void testSAML1AuthnAssertionKeyValue() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML1Constants.CONF_HOLDER_KEY);
        callbackHandler.setCertIdentifier(CERT_IDENTIFIER.KEY_VALUE);
        callbackHandler.setIssuer("www.example.com");

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        samlAssertion.signAssertion("wss40_server", "security", issuerCrypto, false);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        
        WSSecSignatureSAML wsSign = new WSSecSignatureSAML(secHeader);
        wsSign.setUserInfo("wss40", "security");
        wsSign.setDigestAlgo("http://www.w3.org/2001/04/xmlenc#sha256");
        wsSign.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        wsSign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);

        Document signedDoc =
            wsSign.build(userCrypto, samlAssertion, null, null, null);

        String outputString =
            XMLUtils.prettyDocumentToString(signedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 1.1 Authn Assertion Key Value (holder-of-key):");
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains("KeyValue"));

        WSHandlerResult results = verify(signedDoc, userCrypto);
        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.ST_SIGNED).get(0);
        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assert receivedSamlAssertion.isSigned();

        // Test we processed a signature (SOAP body)
        actionResult = results.getActionResults().get(WSConstants.SIGN).get(0);
        assertTrue(actionResult != null);
        assertFalse(actionResult.isEmpty());
        final List<WSDataRef> refs =
            (List<WSDataRef>) actionResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
        assertTrue(refs.size() == 1);

        WSDataRef wsDataRef = refs.get(0);
        String xpath = wsDataRef.getXpath();
        assertEquals("/SOAP-ENV:Envelope/SOAP-ENV:Body", xpath);
    }

    /**
     * Test that creates, sends and processes a signed SAML 2 authentication assertion,
     * where the subject cert is referenced using a Key Value
     */
    @Test
    @SuppressWarnings("unchecked")
    public void testSAML2AuthnAssertionKeyValue() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_HOLDER_KEY);
        callbackHandler.setCertIdentifier(CERT_IDENTIFIER.KEY_VALUE);
        callbackHandler.setIssuer("www.example.com");

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        samlAssertion.signAssertion("wss40_server", "security", issuerCrypto, false);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        
        WSSecSignatureSAML wsSign = new WSSecSignatureSAML(secHeader);
        wsSign.setUserInfo("wss40", "security");
        wsSign.setDigestAlgo("http://www.w3.org/2001/04/xmlenc#sha256");
        wsSign.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        wsSign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);

        Document signedDoc =
            wsSign.build(userCrypto, samlAssertion, null, null, null);

        String outputString =
            XMLUtils.prettyDocumentToString(signedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 2 Authn Assertion Key Value (holder-of-key):");
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains("KeyValue"));

        WSHandlerResult results = verify(signedDoc, userCrypto);
        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.ST_SIGNED).get(0);
        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertTrue(receivedSamlAssertion.isSigned());

        // Test we processed a signature (SOAP body)
        actionResult = results.getActionResults().get(WSConstants.SIGN).get(0);
        assertTrue(actionResult != null);
        assertFalse(actionResult.isEmpty());
        final List<WSDataRef> refs =
            (List<WSDataRef>) actionResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
        assertTrue(refs.size() == 1);

        WSDataRef wsDataRef = refs.get(0);
        String xpath = wsDataRef.getXpath();
        assertEquals("/SOAP-ENV:Envelope/SOAP-ENV:Body", xpath);
    }

    /**
     * Test that creates, sends and processes a signed SAML 1.1 authentication assertion.
     * The difference is that we don't trust the user signature, but as we trust the
     * signature of the issuer, we have (indirect) trust.
     */
    @Test
    @SuppressWarnings("unchecked")
    public void testSAML1AuthnAssertionTrust() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML1Constants.CONF_HOLDER_KEY);
        callbackHandler.setIssuer("www.example.com");
        Crypto crypto = CryptoFactory.getInstance("crypto.properties");
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("16c73ab6-b892-458f-abf5-2f875f74882e");
        X509Certificate[] certs = crypto.getX509Certificates(cryptoType);
        callbackHandler.setCerts(certs);

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        samlAssertion.signAssertion("wss40_server", "security", issuerCrypto, false);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        
        WSSecSignatureSAML wsSign = new WSSecSignatureSAML(secHeader);
        wsSign.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        wsSign.setDigestAlgo("http://www.w3.org/2001/04/xmlenc#sha256");
        wsSign.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        wsSign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);

        Document signedDoc =
            wsSign.build(crypto, samlAssertion, null, null, null);

        String outputString =
            XMLUtils.prettyDocumentToString(signedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed SAML 1.1 Authn Assertion (key holder):");
            LOG.debug(outputString);
        }

        WSHandlerResult results = verify(signedDoc, trustCrypto);

        // Test we processed a SAML assertion
        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.ST_SIGNED).get(0);
        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertTrue(receivedSamlAssertion.isSigned());

        // Test we processed a signature (SOAP body)
        actionResult = results.getActionResults().get(WSConstants.SIGN).get(0);
        assertTrue(actionResult != null);
        assertFalse(actionResult.isEmpty());
        final List<WSDataRef> refs =
            (List<WSDataRef>) actionResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
        assertTrue(refs.size() == 1);

        WSDataRef wsDataRef = refs.get(0);
        String xpath = wsDataRef.getXpath();
        assertEquals("/SOAP-ENV:Envelope/SOAP-ENV:Body", xpath);
    }

    @Test
    @org.junit.Ignore
    public void testSAML2Advice() throws Exception {
        // Create a signed "Advice" Element first
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_BEARER);
        callbackHandler.setIssuer("www.example.com");

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        samlAssertion.signAssertion("wss40_server", "security", issuerCrypto, false);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        Element adviceElement = samlAssertion.toDOM(doc);

        // Now create a SAML Assertion that uses the signed advice Element
        callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.ATTR);
        callbackHandler.setConfirmationMethod(SAML2Constants.CONF_HOLDER_KEY);
        callbackHandler.setIssuer("www.example.com");
        callbackHandler.setAssertionAdviceElement(adviceElement);

        samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        samlAssertion = new SamlAssertionWrapper(samlCallback);

        samlAssertion.signAssertion("wss40_server", "security", issuerCrypto, false);

        byte[] ephemeralKey = callbackHandler.getEphemeralKey();

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        
        WSSecSignatureSAML wsSign = new WSSecSignatureSAML(secHeader);
        wsSign.setUserInfo("wss40", "security");
        wsSign.setDigestAlgo("http://www.w3.org/2001/04/xmlenc#sha256");
        wsSign.setSignatureAlgorithm(WSConstants.HMAC_SHA256);
        wsSign.setKeyIdentifierType(WSConstants.X509_KEY_IDENTIFIER);
        wsSign.setSecretKey(ephemeralKey);

        Document signedDoc =
            wsSign.build(userCrypto, samlAssertion, null, null, null);

        String outputString =
            XMLUtils.prettyDocumentToString(signedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed SAML 2 Attr Assertion (key holder):");
            LOG.debug(outputString);
        }
        System.out.println(outputString);

        /* https://issues.apache.org/jira/browse/WSS-265 */
        WSHandlerResult results = verify(signedDoc, trustCrypto);

        // Test we processed a SAML assertion
        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.ST_SIGNED).get(0);
        SamlAssertionWrapper receivedAssertion =
            (SamlAssertionWrapper) actionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
        assertTrue(receivedAssertion.isSigned());

        // Test we processed a signature (SOAP body)
        actionResult = results.getActionResults().get(WSConstants.SIGN).get(0);
        assertTrue(actionResult != null);
        assertFalse(actionResult.isEmpty());
        @SuppressWarnings("unchecked")
        final List<WSDataRef> refs =
            (List<WSDataRef>) actionResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
        assertTrue(refs.size() == 1);

        WSDataRef wsDataRef = refs.get(0);
        String xpath = wsDataRef.getXpath();
        assertEquals("/SOAP-ENV:Envelope/SOAP-ENV:Body", xpath);
    }

    /**
     * Verifies the soap envelope
     *
     * @param doc
     * @throws Exception Thrown when there is a problem in verification
     */
    private WSHandlerResult verify(Document doc, Crypto sigCrypto) throws Exception {
        WSHandlerResult results =
            secEngine.processSecurityHeader(
                doc, null, callbackHandler, sigCrypto, userCrypto
            );
        String outputString =
            XMLUtils.prettyDocumentToString(doc);
        assertTrue(outputString.indexOf("counter_port_type") > 0 ? true : false);
        return results;
    }

}
