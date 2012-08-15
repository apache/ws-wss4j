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

import org.apache.ws.security.SOAPConstants;
import org.apache.ws.security.WSDataRef;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.common.SAML1CallbackHandler;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.components.crypto.Merlin;
import org.apache.ws.security.saml.SAMLIssuer;
import org.apache.ws.security.saml.SAMLIssuerImpl;
import org.apache.ws.security.saml.SignedSamlTokenHOKTest;
import org.apache.ws.security.saml.WSSecSignatureSAML;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.apache.ws.security.saml.ext.builder.SAML1Constants;
import org.apache.ws.security.util.Loader;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.InputStream;
import java.security.KeyStore;
import java.util.List;
import java.util.ArrayList;
import javax.xml.namespace.QName;

/**
 * This is some unit tests for signing using signature parts. Note that the "soapMsg" below
 * has a custom header added.
 */
public class SignaturePartsTest extends org.junit.Assert {
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(SignaturePartsTest.class);
    private static final String SOAPMSG = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
            "<soapenv:Envelope xmlns:foo=\"urn:foo.bar\" xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" +
            "   <soapenv:Header>" +
            "       <foo:foobar>baz</foo:foobar>" + 
            "   </soapenv:Header>" +
            "   <soapenv:Body>" +
            "      <ns1:testMethod xmlns:ns1=\"http://axis/service/security/test6/LogTestService8\"></ns1:testMethod>" +
            "   </soapenv:Body>" +
            "</soapenv:Envelope>";
    private static final String SOAPMSG_MULTIPLE = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
        "<soapenv:Envelope xmlns:foo=\"urn:foo.bar\" xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" +
        "   <soapenv:Header>" +
        "       <foo:foobar>baz</foo:foobar>" + 
        "   </soapenv:Header>" +
        "   <soapenv:Body>" +
        "      <ns1:testMethod xmlns:ns1=\"http://axis/service/security/test6/LogTestService8\">asf1</ns1:testMethod>" +
        "      <ns1:testMethod xmlns:ns1=\"http://axis/service/security/test6/LogTestService8\">asf2</ns1:testMethod>" +
        "   </soapenv:Body>" +
        "</soapenv:Envelope>";

    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private Crypto crypto = null;
    
    public SignaturePartsTest() throws Exception {
        WSSConfig.init();
        crypto = CryptoFactory.getInstance();
    }

    /**
     * Test signing a custom SOAP header
     */
    @SuppressWarnings("unchecked")
    @org.junit.Test
    public void testSOAPHeader() throws Exception {
        WSSecSignature sign = new WSSecSignature();
        sign.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        sign.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        WSEncryptionPart encP =
            new WSEncryptionPart(
                "foobar",
                "urn:foo.bar",
                "");
        parts.add(encP);
        sign.setParts(parts);
        
        Document signedDoc = sign.build(doc, crypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(signedDoc);
        
        QName name = new QName("urn:foo.bar", "foobar");
        WSSecurityUtil.checkAllElementsProtected(results, WSConstants.SIGN, new QName[]{name});
        try {
            name = new QName("urn:foo.bar", "foobar2");
            WSSecurityUtil.checkAllElementsProtected(results, WSConstants.SIGN, new QName[]{name});
            fail("Failure expected on a wrong protected part");
        } catch (WSSecurityException ex) {
            // expected
        }
        try {
            name = new QName("urn:foo.bar", "foobar");
            WSSecurityUtil.checkAllElementsProtected(results, WSConstants.ENCR, new QName[]{name});
            fail("Failure expected on a wrong action");
        } catch (WSSecurityException ex) {
            // expected
        }
        
        WSSecurityEngineResult actionResult = 
            WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN);
        assertTrue(actionResult != null);
        assertFalse(actionResult.isEmpty());
        final List<WSDataRef> refs =
            (List<WSDataRef>) actionResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
        
        WSDataRef wsDataRef = (WSDataRef)refs.get(0);
        String xpath = wsDataRef.getXpath();
        assertEquals("/soapenv:Envelope/soapenv:Header/foo:foobar", xpath);
        assertEquals(WSConstants.RSA_SHA1, wsDataRef.getAlgorithm());
        
        assertEquals(WSConstants.SHA1, wsDataRef.getDigestAlgorithm());
        
        String sigMethod = (String)actionResult.get(WSSecurityEngineResult.TAG_SIGNATURE_METHOD);
        assertEquals(WSConstants.RSA_SHA1, sigMethod);
        
        String c14nMethod = 
            (String)actionResult.get(WSSecurityEngineResult.TAG_CANONICALIZATION_METHOD);
        assertEquals(WSConstants.C14N_EXCL_OMIT_COMMENTS, c14nMethod);
        
        List<String> transformAlgorithms = wsDataRef.getTransformAlgorithms();
        assertTrue(transformAlgorithms.size() == 1);
        assertTrue(WSConstants.C14N_EXCL_OMIT_COMMENTS.equals(transformAlgorithms.get(0)));
    }
    
    /**
     * Test signing of a header through a STR Dereference Transform
     */
    @SuppressWarnings("unchecked")
    @org.junit.Test
    public void testSOAPHeaderSTRTransform() throws Exception {
        // Construct issuer and user crypto instances
        Crypto issuerCrypto = new Merlin();
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        ClassLoader loader = Loader.getClassLoader(SignedSamlTokenHOKTest.class);
        InputStream input = Merlin.loadInputStream(loader, "keys/wss40_server.jks");
        keyStore.load(input, "security".toCharArray());
        ((Merlin)issuerCrypto).setKeyStore(keyStore);
        
        Crypto userCrypto = CryptoFactory.getInstance("wss40.properties");
        
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

        WSSecSignatureSAML wsSign = new WSSecSignatureSAML();
        wsSign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        wsSign.setUserInfo("wss40", "security");
        
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        WSEncryptionPart encP =
            new WSEncryptionPart("STRTransform", "", "Element");
        parts.add(encP);
        wsSign.setParts(parts);

        //
        // set up for keyHolder
        //
        Document signedDoc = wsSign.build(doc, userCrypto, assertion, null, null, null, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed SAML message (key holder):");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        // Construct trust crypto instance
        Crypto trustCrypto = new Merlin();
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        input = Merlin.loadInputStream(loader, "keys/wss40CA.jks");
        trustStore.load(input, "security".toCharArray());
        ((Merlin)trustCrypto).setTrustStore(trustStore);
        
        List<WSSecurityEngineResult> results = 
            secEngine.processSecurityHeader(doc, null, null, trustCrypto);
        WSSecurityEngineResult stUnsignedActionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.ST_SIGNED);
        AssertionWrapper receivedAssertion = 
            (AssertionWrapper) stUnsignedActionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedAssertion != null);
        assertTrue(receivedAssertion.isSigned());
        
        WSSecurityEngineResult signActionResult = 
            WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN);
        assertTrue(signActionResult != null);
        assertFalse(signActionResult.isEmpty());
        final List<WSDataRef> refs =
            (List<WSDataRef>) signActionResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
        
        WSDataRef wsDataRef = (WSDataRef)refs.get(0);
        String xpath = wsDataRef.getXpath();
        assertEquals("/soapenv:Envelope/soapenv:Header/wsse:Security/saml1:Assertion", xpath);
    }
    
    /**
     * Test signing a custom SOAP header with a bad localname
     */
    @org.junit.Test
    public void testBadLocalname() throws Exception {
        WSSecSignature sign = new WSSecSignature();
        sign.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        sign.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        WSEncryptionPart encP =
            new WSEncryptionPart(
                "foobar2",
                "urn:foo.bar",
                "");
        parts.add(encP);
        sign.setParts(parts);
        
        try {
            sign.build(doc, crypto, secHeader);
            fail("Failure expected on a bad localname");
        } catch (WSSecurityException ex) {
            // expected
        }
    }
    
    /**
     * Test signing a custom SOAP header with a bad namespace
     */
    @org.junit.Test
    public void testBadNamespace() throws Exception {
        WSSecSignature sign = new WSSecSignature();
        sign.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        sign.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        WSEncryptionPart encP =
            new WSEncryptionPart(
                "foobar",
                "urn:foo.bar2",
                "");
        parts.add(encP);
        sign.setParts(parts);
        
        try {
            sign.build(doc, crypto, secHeader);
            fail("Failure expected on a bad namespace");
        } catch (WSSecurityException ex) {
            // expected
        }
    }
    
    /**
     * Test signing a custom SOAP header and the SOAP body
     */
    @org.junit.Test
    public void testSOAPHeaderAndBody() throws Exception {
        WSSecSignature sign = new WSSecSignature();
        sign.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        sign.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        SOAPConstants soapConstants = 
            WSSecurityUtil.getSOAPConstants(doc.getDocumentElement());

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        WSEncryptionPart encP =
            new WSEncryptionPart(
                soapConstants.getBodyQName().getLocalPart(),    // define the body
                soapConstants.getEnvelopeURI(),
                "");
        parts.add(encP);
        WSEncryptionPart encP2 =
            new WSEncryptionPart(
                "foobar",
                "urn:foo.bar",
                "");
        parts.add(encP2);
        sign.setParts(parts);
        
        Document signedDoc = sign.build(doc, crypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(signedDoc);
        
        QName fooName = new QName("urn:foo.bar", "foobar");
        QName bodyName = new QName(soapConstants.getEnvelopeURI(), "Body");
        WSSecurityUtil.checkAllElementsProtected(results, WSConstants.SIGN, new QName[]{fooName});
        WSSecurityUtil.checkAllElementsProtected(results, WSConstants.SIGN, new QName[]{bodyName});
        WSSecurityUtil.checkAllElementsProtected(
            results, 
            WSConstants.SIGN, 
            new QName[]{bodyName, fooName}
        );
        WSSecurityUtil.checkAllElementsProtected(
            results, 
            WSConstants.SIGN, 
            new QName[]{fooName, bodyName}
        );
        try {
            WSSecurityUtil.checkAllElementsProtected(
                results, 
                WSConstants.ENCR, 
                new QName[]{fooName, bodyName}
            );
            fail("Failure expected on a wrong action");
        } catch (WSSecurityException ex) {
            // expected
        }
        try {
            QName headerName = new QName(soapConstants.getEnvelopeURI(), "Header");
            WSSecurityUtil.checkAllElementsProtected(
                results, 
                WSConstants.SIGN, 
                new QName[]{fooName, bodyName, headerName}
            );
            fail("Failure expected on an unsatisfied requirement");
        } catch (WSSecurityException ex) {
            // expected
        }
    }
    
    
    /**
     * Test getting a DOM Element from WSEncryptionPart directly
     */
    @org.junit.Test
    public void testSignaturePartDOMElement() throws Exception {
        WSSecSignature sign = new WSSecSignature();
        sign.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        sign.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        SOAPConstants soapConstants = 
            WSSecurityUtil.getSOAPConstants(doc.getDocumentElement());

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        // Give wrong names to make sure it's picking up the element
        WSEncryptionPart encP =
            new WSEncryptionPart(
                "Incorrect Localname",
                "Incorrect N/S",
                "");
        Element bodyElement = WSSecurityUtil.findBodyElement(doc);
        assertTrue(bodyElement != null && "Body".equals(bodyElement.getLocalName()));
        encP.setElement(bodyElement);
        parts.add(encP);
        sign.setParts(parts);
        
        Document signedDoc = sign.build(doc, crypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(signedDoc);
        
        QName bodyName = new QName(soapConstants.getEnvelopeURI(), "Body");
        WSSecurityUtil.checkAllElementsProtected(results, WSConstants.SIGN, new QName[]{bodyName});
    }
    
    /**
     * Test signing two SOAP Body elements with the same QName.
     */
    @org.junit.Test
    public void testMultipleElements() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG_MULTIPLE);
        WSSecSignature sign = new WSSecSignature();
        sign.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        sign.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        WSEncryptionPart encP =
            new WSEncryptionPart(
                "testMethod",
                "http://axis/service/security/test6/LogTestService8",
                "");
        parts.add(encP);
        sign.setParts(parts);
        
        Document signedDoc = sign.build(doc, crypto, secHeader);
        
        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        
        verify(signedDoc);
    }
    

    /**
     * Verifies the soap envelope
     * <p/>
     * 
     * @param doc 
     * @throws Exception Thrown when there is a problem in verification
     */
    private List<WSSecurityEngineResult> verify(Document doc) throws Exception {
        List<WSSecurityEngineResult> results = 
            secEngine.processSecurityHeader(doc, null, null, crypto);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Verfied and decrypted message:");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        return results;
    }

}
