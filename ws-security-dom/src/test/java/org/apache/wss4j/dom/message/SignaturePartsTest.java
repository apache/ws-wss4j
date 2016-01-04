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

package org.apache.wss4j.dom.message;

import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.dom.SOAPConstants;
import org.apache.wss4j.dom.WSDataRef;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.common.SAML1CallbackHandler;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.crypto.Merlin;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SAMLCallback;
import org.apache.wss4j.common.saml.SAMLUtil;
import org.apache.wss4j.common.saml.builder.SAML1Constants;
import org.apache.wss4j.common.util.Loader;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.saml.SignedSamlTokenHOKTest;
import org.apache.wss4j.dom.saml.WSSecSignatureSAML;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.InputStream;
import java.security.KeyStore;
import java.util.List;

import javax.xml.namespace.QName;

/**
 * This is some unit tests for signing using signature parts. Note that the "soapMsg" below
 * has a custom header added.
 */
public class SignaturePartsTest extends org.junit.Assert {
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(SignaturePartsTest.class);
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

    @org.junit.AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }

    public SignaturePartsTest() throws Exception {
        WSSConfig.init();
        crypto = CryptoFactory.getInstance();
    }

    /**
     * Test signing a custom SOAP header
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testSOAPHeader() throws Exception {
        WSSecSignature sign = new WSSecSignature();
        sign.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        sign.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSEncryptionPart encP =
            new WSEncryptionPart(
                "foobar",
                "urn:foo.bar",
                "");
        sign.getParts().add(encP);

        Document signedDoc = sign.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        WSHandlerResult results = verify(signedDoc);

        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.SIGN).get(0);
        assertTrue(actionResult != null);
        assertFalse(actionResult.isEmpty());
        final List<WSDataRef> refs =
            (List<WSDataRef>) actionResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);

        WSDataRef wsDataRef = refs.get(0);
        String xpath = wsDataRef.getXpath();
        assertEquals("/soapenv:Envelope/soapenv:Header/foo:foobar", xpath);
        assertEquals(WSConstants.RSA_SHA1, wsDataRef.getAlgorithm());
        assertNotNull(wsDataRef.getDigestValue());
        assertTrue(wsDataRef.getDigestValue().length > 0);
        QName expectedQName = new QName("urn:foo.bar", "foobar");
        assertEquals(expectedQName, wsDataRef.getName());

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

    @Test
    public void testOptionalSOAPHeaderPresent() throws Exception {
        WSSecSignature sign = new WSSecSignature();
        sign.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        sign.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSEncryptionPart encP =
            new WSEncryptionPart(
                "foobar",
                "urn:foo.bar",
                "");
        encP.setRequired(false);
        sign.getParts().add(encP);
        String soapNamespace = WSSecurityUtil.getSOAPNamespace(doc.getDocumentElement());
        encP =
            new WSEncryptionPart(
                WSConstants.ELEM_BODY,
                soapNamespace,
                "Content"
            );
        sign.getParts().add(encP);

        Document signedDoc = sign.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        verify(signedDoc);
    }

    @Test
    public void testOptionalSOAPHeaderNotPresent() throws Exception {
        WSSecSignature sign = new WSSecSignature();
        sign.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        sign.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSEncryptionPart encP =
            new WSEncryptionPart(
                "foobar",
                "urn:foo.bar",
                "");
        encP.setRequired(false);
        sign.getParts().add(encP);
        String soapNamespace = WSSecurityUtil.getSOAPNamespace(doc.getDocumentElement());
        encP =
            new WSEncryptionPart(
                WSConstants.ELEM_BODY,
                soapNamespace,
                "Content"
            );
        sign.getParts().add(encP);

        Document signedDoc = sign.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        verify(signedDoc);
    }

    @Test
    public void testRequiredSOAPHeaderNotPresent() throws Exception {
        WSSecSignature sign = new WSSecSignature();
        sign.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        sign.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSEncryptionPart encP =
            new WSEncryptionPart(
                "foobar",
                "urn:foo.bar",
                "");
        sign.getParts().add(encP);
        String soapNamespace = WSSecurityUtil.getSOAPNamespace(doc.getDocumentElement());
        encP =
            new WSEncryptionPart(
                WSConstants.ELEM_BODY,
                soapNamespace,
                "Content"
            );
        sign.getParts().add(encP);

        try {
            sign.build(doc, crypto, secHeader);
            fail("Failure expected on not signing a required element");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.FAILED_SIGNATURE);
        }
    }

    /**
     * Test signing of a header through a STR Dereference Transform
     */
    @SuppressWarnings("unchecked")
    @Test
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

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);

        samlCallback.setIssuer("www.example.com");

        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);
        samlAssertion.signAssertion("wss40_server", "security", issuerCrypto, false);

        WSSecSignatureSAML wsSign = new WSSecSignatureSAML();
        wsSign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        wsSign.setUserInfo("wss40", "security");

        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSEncryptionPart encP =
            new WSEncryptionPart("STRTransform", "", "Element");
        wsSign.getParts().add(encP);

        //
        // set up for keyHolder
        //
        Document signedDoc = wsSign.build(doc, userCrypto, samlAssertion, null, null, null, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed SAML message (key holder):");
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        // Construct trust crypto instance
        Crypto trustCrypto = new Merlin();
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        input = Merlin.loadInputStream(loader, "keys/wss40CA.jks");
        trustStore.load(input, "security".toCharArray());
        ((Merlin)trustCrypto).setTrustStore(trustStore);

        WSHandlerResult results =
            secEngine.processSecurityHeader(doc, null, null, trustCrypto);
        WSSecurityEngineResult stUnsignedActionResult =
            results.getActionResults().get(WSConstants.ST_SIGNED).get(0);
        SamlAssertionWrapper receivedSamlAssertion =
            (SamlAssertionWrapper) stUnsignedActionResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
        assertTrue(receivedSamlAssertion != null);
        assertTrue(receivedSamlAssertion.isSigned());

        WSSecurityEngineResult signActionResult =
            results.getActionResults().get(WSConstants.SIGN).get(0);
        assertTrue(signActionResult != null);
        assertFalse(signActionResult.isEmpty());
        final List<WSDataRef> refs =
            (List<WSDataRef>) signActionResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);

        WSDataRef wsDataRef = refs.get(0);
        String xpath = wsDataRef.getXpath();
        assertEquals("/soapenv:Envelope/soapenv:Header/wsse:Security/saml1:Assertion", xpath);
    }

    /**
     * Test signing a custom SOAP header with a bad localname
     */
    @Test
    public void testBadLocalname() throws Exception {
        WSSecSignature sign = new WSSecSignature();
        sign.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        sign.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSEncryptionPart encP =
            new WSEncryptionPart(
                "foobar2",
                "urn:foo.bar",
                "");
        sign.getParts().add(encP);

        try {
            sign.build(doc, crypto, secHeader);
            fail("Failure expected on a bad localname");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.FAILED_SIGNATURE);
        }
    }

    /**
     * Test signing a custom SOAP header with a bad namespace
     */
    @Test
    public void testBadNamespace() throws Exception {
        WSSecSignature sign = new WSSecSignature();
        sign.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        sign.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSEncryptionPart encP =
            new WSEncryptionPart(
                "foobar",
                "urn:foo.bar2",
                "");
        sign.getParts().add(encP);

        try {
            sign.build(doc, crypto, secHeader);
            fail("Failure expected on a bad namespace");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.FAILED_SIGNATURE);
        }
    }

    /**
     * Test signing a custom SOAP header and the SOAP body
     */
    @Test
    public void testSOAPHeaderAndBody() throws Exception {
        WSSecSignature sign = new WSSecSignature();
        sign.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        sign.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        SOAPConstants soapConstants =
            WSSecurityUtil.getSOAPConstants(doc.getDocumentElement());

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSEncryptionPart encP =
            new WSEncryptionPart(
                soapConstants.getBodyQName().getLocalPart(),    // define the body
                soapConstants.getEnvelopeURI(),
                "");
        sign.getParts().add(encP);
        WSEncryptionPart encP2 =
            new WSEncryptionPart(
                "foobar",
                "urn:foo.bar",
                "");
        sign.getParts().add(encP2);

        Document signedDoc = sign.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        WSHandlerResult results = verify(signedDoc);

        QName fooName = new QName("urn:foo.bar", "foobar");
        QName bodyName = new QName(soapConstants.getEnvelopeURI(), "Body");
        QName headerName = new QName(soapConstants.getEnvelopeURI(), "Header");

        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.SIGN).get(0);
        assertTrue(actionResult != null);
        assertFalse(actionResult.isEmpty());

        @SuppressWarnings("unchecked")
        final List<WSDataRef> refs =
            (List<WSDataRef>) actionResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
        assertTrue(refs != null && !refs.isEmpty());

        boolean foundFoo = false;
        boolean foundBody = false;
        boolean foundHeader = false;
        for (WSDataRef ref : refs) {
            if (fooName.equals(ref.getName())) {
                foundFoo = true;
            } else if (bodyName.equals(ref.getName())) {
                foundBody = true;
            } else if (headerName.equals(ref.getName())) {
                foundHeader = true;
            }
        }
        assertTrue(foundFoo && foundBody);
        assertFalse(foundHeader);
    }


    /**
     * Test getting a DOM Element from WSEncryptionPart directly
     */
    @Test
    public void testSignaturePartDOMElement() throws Exception {
        WSSecSignature sign = new WSSecSignature();
        sign.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        sign.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        SOAPConstants soapConstants =
            WSSecurityUtil.getSOAPConstants(doc.getDocumentElement());

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        // Give wrong names to make sure it's picking up the element
        WSEncryptionPart encP =
            new WSEncryptionPart(
                "Incorrect Localname",
                "Incorrect N/S",
                "");
        Element bodyElement = WSSecurityUtil.findBodyElement(doc);
        assertTrue(bodyElement != null && "Body".equals(bodyElement.getLocalName()));
        encP.setElement(bodyElement);
        sign.getParts().add(encP);

        Document signedDoc = sign.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        WSHandlerResult results = verify(signedDoc);

        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.SIGN).get(0);
        assertTrue(actionResult != null);
        assertFalse(actionResult.isEmpty());
        @SuppressWarnings("unchecked")
        final List<WSDataRef> refs =
            (List<WSDataRef>) actionResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);

        WSDataRef wsDataRef = refs.get(0);
        QName bodyName = new QName(soapConstants.getEnvelopeURI(), "Body");
        assertEquals(bodyName, wsDataRef.getName());
    }

    /**
     * Test signing two SOAP Body elements with the same QName.
     */
    @Test
    public void testMultipleElements() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG_MULTIPLE);
        WSSecSignature sign = new WSSecSignature();
        sign.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        sign.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSEncryptionPart encP =
            new WSEncryptionPart(
                "testMethod",
                "http://axis/service/security/test6/LogTestService8",
                "");
        sign.getParts().add(encP);

        Document signedDoc = sign.build(doc, crypto, secHeader);

        String outputString =
            XMLUtils.prettyDocumentToString(signedDoc);
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
    private WSHandlerResult verify(Document doc) throws Exception {
        WSHandlerResult results =
            secEngine.processSecurityHeader(doc, null, null, crypto);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Verfied and decrypted message:");
            String outputString =
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        return results;
    }

}
