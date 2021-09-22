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

import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.callback.CallbackHandler;

import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SAMLCallback;
import org.apache.wss4j.common.saml.SAMLUtil;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.saml.builder.SAML1Constants;
import org.apache.wss4j.common.util.DateUtil;
import org.apache.wss4j.common.util.KeyUtils;
import org.apache.wss4j.common.util.SOAPUtil;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.common.KeystoreCallbackHandler;
import org.apache.wss4j.dom.common.SAML1CallbackHandler;

import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.dom.saml.WSSecSignatureSAML;
import org.apache.wss4j.dom.util.SignatureUtils;
import org.apache.wss4j.dom.util.WSSecurityUtil;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * This class tests the modification of requests.
 */
public class ModifiedRequestTest {
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(ModifiedRequestTest.class);
    private static final String SOAPMSG =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        + "<SOAP-ENV:Envelope "
        +   "xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" "
        +   "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" "
        +   "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">"
        +   "<SOAP-ENV:Body>"
        +       "<add xmlns=\"http://ws.apache.org/counter/counter_port_type\">"
        +           "<value xmlns=\"http://blah.com\">15</value>"
        +       "</add>"
        +   "</SOAP-ENV:Body>"
        + "</SOAP-ENV:Envelope>";

    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private CallbackHandler callbackHandler = new KeystoreCallbackHandler();
    private Crypto crypto;

    public ModifiedRequestTest() throws Exception {
        WSSConfig.init();
        crypto = CryptoFactory.getInstance();
    }

    /**
     * Test that signs a SOAP body element "value". The SOAP request is then modified
     * so that the signed "value" element is put in the header, and the value of the
     * original element is changed. This test will fail as the request will contain
     * multiple elements with the same wsu:Id.
     */
    @Test
    public void testMovedElement() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecSignature builder = new WSSecSignature(secHeader);
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        LOG.info("Before Signing....");

        WSEncryptionPart encP =
            new WSEncryptionPart(
                "value",
                "http://blah.com",
                "");
        builder.getParts().add(encP);

        Document signedDoc = builder.build(crypto);

        //
        // Replace the signed element with a modified element, and move the original
        // signed element into the SOAP header
        //
        Element secHeaderElement = secHeader.getSecurityHeaderElement();
        Element envelopeElement = signedDoc.getDocumentElement();
        Node valueNode =
            envelopeElement.getElementsByTagNameNS("http://blah.com", "value").item(0);
        Node clonedValueNode = valueNode.cloneNode(true);
        secHeaderElement.appendChild(clonedValueNode);
        valueNode.getFirstChild().setNodeValue("250");

        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        try {
            verify(signedDoc);
            fail("Failure expected on multiple elements with the same wsu:Id");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.FAILED_CHECK);
            assertTrue(ex.getMessage().startsWith("javax.xml.crypto.URIReferenceException: " +
                    "org.apache.xml.security.utils.resolver.ResourceResolverException: "));
        }
    }


    /**
     * Test that signs a SOAP body element "value". The SOAP request is then modified
     * so that the signed "value" element is put in the header, and the value of the
     * original element is changed. The wsu:Id value of the original element is also
     * changed. Signature verification will pass, so we need to check the Elements.
     */
    @Test
    public void testMovedElementChangedId() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecSignature builder = new WSSecSignature(secHeader);
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        LOG.info("Before Signing....");

        WSEncryptionPart encP =
            new WSEncryptionPart(
                "value",
                "http://blah.com",
                "");
        builder.getParts().add(encP);

        Document signedDoc = builder.build(crypto);

        //
        // Replace the signed element with a modified element, and move the original
        // signed element into the SOAP header
        //
        Element secHeaderElement = secHeader.getSecurityHeaderElement();
        Element envelopeElement = signedDoc.getDocumentElement();
        Node valueNode =
            envelopeElement.getElementsByTagNameNS("http://blah.com", "value").item(0);
        Node clonedValueNode = valueNode.cloneNode(true);
        secHeaderElement.appendChild(clonedValueNode);
        valueNode.getFirstChild().setNodeValue("250");
        ((Element)valueNode).setAttributeNS(
             WSConstants.WSU_NS, "wsu:Id", "id-250"
        );

        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        //
        // Check the signature...this should pass
        //
        WSHandlerResult results = verify(signedDoc);

        //
        // Finally we need to check that the Element that was signed is what we expect to be signed
        //
        envelopeElement = signedDoc.getDocumentElement();
        Node bodyNode =
            envelopeElement.getElementsByTagNameNS(
                WSConstants.URI_SOAP11_ENV, "Body"
            ).item(0);
        valueNode =
            ((Element)bodyNode).getElementsByTagNameNS(
                "http://blah.com", "value"
            ).item(0);

        List<WSSecurityEngineResult> signedResults =
            results.getActionResults().get(WSConstants.SIGN);
        try {
            SignatureUtils.verifySignedElement((Element)valueNode, signedResults);
            fail("Failure expected on the required element not being signed");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.FAILED_CHECK);
        }
    }

    /**
     * Test a duplicated signed SAML Assertion.
     */
    @Test
    public void testDuplicatedSignedSAMLAssertion() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML1Constants.CONF_SENDER_VOUCHES);
        callbackHandler.setIssuer("www.example.com");

        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecSignatureSAML wsSign = new WSSecSignatureSAML(secHeader);
        wsSign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);

        Document signedDoc =
            wsSign.build(
                 null, samlAssertion, crypto, "16c73ab6-b892-458f-abf5-2f875f74882e", "security"
            );
        Element assertionElement = (Element) samlAssertion.getElement().cloneNode(true);
        assertionElement.removeChild(assertionElement.getFirstChild());
        secHeader.getSecurityHeaderElement().appendChild(assertionElement);

        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 1.1 Authn Assertion (sender vouches):");
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        try {
            verify(signedDoc);
            fail("Failure expected on duplicate tokens");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getMessage().contains(
                "Multiple security tokens with the same Id have been detected"
            ));
        }
    }

    /**
     * Test a duplicated signed UsernameToken
     */
    @Test
    public void testDuplicatedSignedUsernameToken() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecUsernameToken usernameToken = new WSSecUsernameToken(secHeader);
        usernameToken.setUserInfo("wss86", "security");
        usernameToken.build();

        WSSecSignature builder = new WSSecSignature(secHeader);
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");

        WSEncryptionPart encP =
            new WSEncryptionPart(
                "UsernameToken",
                WSConstants.WSSE_NS,
                "");
        builder.getParts().add(encP);

        builder.prepare(crypto);

        List<javax.xml.crypto.dsig.Reference> referenceList =
            builder.addReferencesToSign(builder.getParts());

        builder.computeSignature(referenceList, false, null);

        secHeader.getSecurityHeaderElement().appendChild(
            usernameToken.getUsernameTokenElement().cloneNode(true)
        );

        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed Timestamp");
            String outputString =
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        try {
            verify(doc);
            fail("Failure expected on duplicate tokens");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getMessage().contains(
                "Multiple security tokens with the same Id have been detected"
            ));
        }
    }

    /**
     * Test for when an EncryptedData structure is modified
     */
    @Test
    public void testModifiedEncryptedDataStructure() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecEncrypt builder = new WSSecEncrypt(secHeader);
        builder.setUserInfo("wss40");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        builder.setSymmetricEncAlgorithm(WSConstants.TRIPLE_DES);

        Crypto wssCrypto = CryptoFactory.getInstance("wss40.properties");
        KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.TRIPLE_DES);
        SecretKey symmetricKey = keyGen.generateKey();
        Document encryptedDoc = builder.build(wssCrypto, symmetricKey);

        Element body = WSSecurityUtil.findBodyElement(doc);
        Element encryptionMethod =
            XMLUtils.findElement(body, "EncryptionMethod", WSConstants.ENC_NS);
        encryptionMethod.setAttributeNS(null, "Algorithm", "http://new-algorithm");

        String outputString =
            XMLUtils.prettyDocumentToString(encryptedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }

        WSSecurityEngine newEngine = new WSSecurityEngine();
        try {
            newEngine.processSecurityHeader(doc, null, new KeystoreCallbackHandler(), wssCrypto);
            fail("Failure expected on a modified EncryptedData structure");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY);
        }
    }

    /**
     * Test for when some EncryptedData CipherValue data is modified.
     */
    @Test
    public void testModifiedEncryptedDataCipherValue() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecEncrypt builder = new WSSecEncrypt(secHeader);
        builder.setUserInfo("wss40");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        builder.setSymmetricEncAlgorithm(WSConstants.TRIPLE_DES);

        Crypto wssCrypto = CryptoFactory.getInstance("wss40.properties");
        KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.TRIPLE_DES);
        SecretKey symmetricKey = keyGen.generateKey();
        Document encryptedDoc = builder.build(wssCrypto, symmetricKey);

        Element body = WSSecurityUtil.findBodyElement(doc);
        Element cipherValue =
            XMLUtils.findElement(body, "CipherValue", WSConstants.ENC_NS);
        String cipherText = cipherValue.getTextContent();

        StringBuilder stringBuilder = new StringBuilder(cipherText);
        int index = stringBuilder.length() / 2;
        char ch = stringBuilder.charAt(index);
        if (ch != 'A') {
            ch = 'A';
        } else {
            ch = 'B';
        }
        stringBuilder.setCharAt(index, ch);
        cipherValue.setTextContent(stringBuilder.toString());

        String outputString =
            XMLUtils.prettyDocumentToString(encryptedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }

        WSSecurityEngine newEngine = new WSSecurityEngine();
        try {
            newEngine.processSecurityHeader(doc, null, new KeystoreCallbackHandler(), wssCrypto);
            fail("Failure expected on a modified EncryptedData CipherValue");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.FAILED_CHECK);
        }
    }

    /**
     * Test for when some EncryptedData CipherValue data is modified
     * (in the security header)
     */
    @Test
    public void testModifiedSecurityHeaderEncryptedDataCipherValue() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecEncrypt builder = new WSSecEncrypt(secHeader);
        builder.setUserInfo("wss40");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        builder.setSymmetricEncAlgorithm(WSConstants.TRIPLE_DES);

        Crypto wssCrypto = CryptoFactory.getInstance("wss40.properties");

        WSSecTimestamp timestamp = new WSSecTimestamp(secHeader);
        timestamp.setTimeToLive(300);
        timestamp.build();

        WSEncryptionPart encP =
            new WSEncryptionPart(
                "Timestamp",
                WSConstants.WSU_NS,
                "");
        builder.getParts().add(encP);

        KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.TRIPLE_DES);
        SecretKey symmetricKey = keyGen.generateKey();
        Document encryptedDoc = builder.build(wssCrypto, symmetricKey);

        Element securityHeader =
            WSSecurityUtil.getSecurityHeader(encryptedDoc, "");
        Element encryptedTimestamp =
            XMLUtils.findElement(securityHeader, "EncryptedData", WSConstants.ENC_NS);
        Element cipherValue =
            XMLUtils.findElement(encryptedTimestamp, "CipherValue", WSConstants.ENC_NS);
        String cipherText = cipherValue.getTextContent();

        StringBuilder stringBuilder = new StringBuilder(cipherText);
        int index = stringBuilder.length() / 2;
        char ch = stringBuilder.charAt(index);
        if (ch != 'A') {
            ch = 'A';
        } else {
            ch = 'B';
        }
        stringBuilder.setCharAt(index, ch);
        cipherValue.setTextContent(stringBuilder.toString());

        String outputString =
            XMLUtils.prettyDocumentToString(encryptedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }

        WSSecurityEngine newEngine = new WSSecurityEngine();
        try {
            newEngine.processSecurityHeader(doc, null, new KeystoreCallbackHandler(), wssCrypto);
            fail("Failure expected on a modified EncryptedData CipherValue");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.FAILED_CHECK);
        }
    }

    /**
     * Test for when some EncryptedKey CipherValue data is modified.
     */
    @Test
    public void testModifiedEncryptedKeyCipherValue() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecEncrypt builder = new WSSecEncrypt(secHeader);
        builder.setUserInfo("wss40");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        builder.setSymmetricEncAlgorithm(WSConstants.TRIPLE_DES);

        Crypto wssCrypto = CryptoFactory.getInstance("wss40.properties");
        KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.TRIPLE_DES);
        SecretKey symmetricKey = keyGen.generateKey();
        Document encryptedDoc = builder.build(wssCrypto, symmetricKey);

        Element encryptedKey =
            XMLUtils.findElement(doc.getDocumentElement(), "EncryptedKey", WSConstants.ENC_NS);
        Element cipherValue =
            XMLUtils.findElement(encryptedKey, "CipherValue", WSConstants.ENC_NS);
        String cipherText = cipherValue.getTextContent();

        StringBuilder stringBuilder = new StringBuilder(cipherText);
        int index = stringBuilder.length() / 2;
        char ch = stringBuilder.charAt(index);
        if (ch != 'A') {
            ch = 'A';
        } else {
            ch = 'B';
        }
        stringBuilder.setCharAt(index, ch);
        cipherValue.setTextContent(stringBuilder.toString());

        String outputString =
            XMLUtils.prettyDocumentToString(encryptedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }

        WSSecurityEngine newEngine = new WSSecurityEngine();
        try {
            newEngine.processSecurityHeader(doc, null, new KeystoreCallbackHandler(), wssCrypto);
            fail("Failure expected on a modified EncryptedData CipherValue");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.FAILED_CHECK);
        }
    }



    /**
     * Test for when an element that a Signature Reference points to is modified
     */
    @Test
    public void testModifiedSignatureReference() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecSignature builder = new WSSecSignature(secHeader);
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");

        WSSecTimestamp timestamp = new WSSecTimestamp(secHeader);
        timestamp.setTimeToLive(300);
        timestamp.build();

        WSEncryptionPart encP =
            new WSEncryptionPart(
                "Timestamp",
                WSConstants.WSU_NS,
                "");
        builder.getParts().add(encP);

        Document signedDoc = builder.build(crypto);

        // Modify the Created text of the Timestamp element
        Element timestampElement = timestamp.getElement();
        Element createdValue =
            XMLUtils.findElement(timestampElement, "Created", WSConstants.WSU_NS);

        // Add 5 seconds
        ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC).plusSeconds(5L);
        createdValue.setTextContent(DateUtil.getDateTimeFormatter(true).format(now));

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        try {
            verify(signedDoc);
            fail("Failure expected on a modified Signature Reference");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.FAILED_CHECK);
        }
    }

    /**
     * Test for when a Signature is received with a certificate that is not trusted
     */
    @Test
    public void testUntrustedSignature() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecSignature builder = new WSSecSignature(secHeader);
        builder.setUserInfo("wss40", "security");

        Crypto wss40Crypto = CryptoFactory.getInstance("wss40.properties");
        Document signedDoc = builder.build(wss40Crypto);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        try {
            verify(signedDoc);
            fail("Failure expected on an untrusted Certificate");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.FAILED_CHECK);
        }
    }

    /**
     * Test for when the Signature element is modified
     */
    @Test
    public void testModifiedSignature() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecSignature builder = new WSSecSignature(secHeader);
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");

        Document signedDoc = builder.build(crypto);

        // Modify the Signature element
        Element signatureElement = builder.getSignatureElement();
        Node firstChild = signatureElement.getFirstChild();
        while (!(firstChild instanceof Element) && firstChild != null) {
            firstChild = signatureElement.getNextSibling();
        }
        ((Element)firstChild).setAttributeNS(null, "Id", "xyz");

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        try {
            verify(signedDoc);
            fail("Failure expected on a modified Signature element");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.FAILED_CHECK);
        }
    }

    /**
     * Verifies the soap envelope
     * <p/>
     *
     * @param doc soap envelope
     * @throws java.lang.Exception Thrown when there is a problem in verification
     */
    private WSHandlerResult verify(Document doc) throws Exception {
        return secEngine.processSecurityHeader(doc, null, callbackHandler, crypto);
    }

}