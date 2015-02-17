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

import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSSConfig;
import org.apache.wss4j.dom.WSSecurityEngine;
import org.apache.wss4j.dom.WSSecurityEngineResult;
import org.apache.wss4j.dom.common.KeystoreCallbackHandler;
import org.apache.wss4j.dom.common.SAML1CallbackHandler;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.saml.SAMLCallback;
import org.apache.wss4j.common.saml.SAMLUtil;
import org.apache.wss4j.common.saml.builder.SAML1Constants;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.saml.WSSecSignatureSAML;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.apache.wss4j.dom.util.XmlSchemaDateFormat;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.text.DateFormat;
import java.util.Date;
import java.util.List;

import javax.security.auth.callback.CallbackHandler;
import javax.xml.datatype.Duration;
import javax.xml.datatype.XMLGregorianCalendar;

/**
 * This class tests the modification of requests.
 */
public class ModifiedRequestTest extends org.junit.Assert {
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
    private Crypto crypto = null;
    
    @org.junit.AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }
    
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
    @org.junit.Test
    public void testMovedElement() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        LOG.info("Before Signing....");
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        WSEncryptionPart encP =
            new WSEncryptionPart(
                "value",
                "http://blah.com",
                "");
        builder.getParts().add(encP);
        
        Document signedDoc = builder.build(doc, crypto, secHeader);
        
        //
        // Replace the signed element with a modified element, and move the original
        // signed element into the SOAP header
        //
        org.w3c.dom.Element secHeaderElement = secHeader.getSecurityHeader();
        org.w3c.dom.Element envelopeElement = signedDoc.getDocumentElement();
        org.w3c.dom.Node valueNode = 
            envelopeElement.getElementsByTagNameNS("http://blah.com", "value").item(0);
        org.w3c.dom.Node clonedValueNode = valueNode.cloneNode(true);
        secHeaderElement.appendChild(clonedValueNode);
        valueNode.getFirstChild().setNodeValue("250");
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        try {
            verify(signedDoc);
            fail("Failure expected on multiple elements with the same wsu:Id");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.FAILED_CHECK);
            assertTrue(ex.getMessage().startsWith("javax.xml.crypto.URIReferenceException: " +
                    "org.apache.xml.security.utils.resolver.ResourceResolverException: " +
                    "Cannot resolve element with ID "));
        }
    }
    
    
    /**
     * Test that signs a SOAP body element "value". The SOAP request is then modified
     * so that the signed "value" element is put in the header, and the value of the
     * original element is changed. The wsu:Id value of the original element is also
     * changed. Signature verification will pass, so we need to check the wsu:Id's.
     */
    @org.junit.Test
    public void testMovedElementChangedId() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        LOG.info("Before Signing....");
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        WSEncryptionPart encP =
            new WSEncryptionPart(
                "value",
                "http://blah.com",
                "");
        builder.getParts().add(encP);
        
        Document signedDoc = builder.build(doc, crypto, secHeader);
        
        //
        // Replace the signed element with a modified element, and move the original
        // signed element into the SOAP header
        //
        org.w3c.dom.Element secHeaderElement = secHeader.getSecurityHeader();
        org.w3c.dom.Element envelopeElement = signedDoc.getDocumentElement();
        org.w3c.dom.Node valueNode = 
            envelopeElement.getElementsByTagNameNS("http://blah.com", "value").item(0);
        org.w3c.dom.Node clonedValueNode = valueNode.cloneNode(true);
        secHeaderElement.appendChild(clonedValueNode);
        valueNode.getFirstChild().setNodeValue("250");
        String savedId = 
            ((org.w3c.dom.Element)valueNode).getAttributeNS(WSConstants.WSU_NS, "Id");
        ((org.w3c.dom.Element)valueNode).setAttributeNS(
             WSConstants.WSU_NS, "wsu:Id", "id-250"
        );
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        //
        // Now we check that the wsu:Id of the element we want signed corresponds to the
        // wsu:Id that was actually signed...again, this should pass
        //
        List<WSSecurityEngineResult> results = verify(signedDoc);
        
        WSSecurityEngineResult actionResult = 
            WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN);
        WSSecurityUtil.checkSignsAllElements(actionResult, new String[]{savedId});
        
        //
        // Finally we need to check that the wsu:Id of the element we want signed in the
        // SOAP request is the same as the wsu:Id that was actually signed
        //
        envelopeElement = signedDoc.getDocumentElement();
        org.w3c.dom.Node bodyNode = 
            envelopeElement.getElementsByTagNameNS(
                WSConstants.URI_SOAP11_ENV, "Body"
            ).item(0);
        valueNode = 
            ((org.w3c.dom.Element)bodyNode).getElementsByTagNameNS(
                "http://blah.com", "value"
            ).item(0);
        String actualId = 
            ((org.w3c.dom.Element)valueNode).getAttributeNS(WSConstants.WSU_NS, "Id");
        try {
            WSSecurityUtil.checkSignsAllElements(actionResult, new String[]{actualId});
            fail("Failure expected on bad wsu:Id");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.FAILED_CHECK);
            assertEquals("Element id-250 is not included in the signature", ex.getMessage());
        }
    }
    
    /**
     * Test a duplicated signed SAML Assertion.
     */
    @org.junit.Test
    public void testDuplicatedSignedSAMLAssertion() throws Exception {
        SAML1CallbackHandler callbackHandler = new SAML1CallbackHandler();
        callbackHandler.setStatement(SAML1CallbackHandler.Statement.AUTHN);
        callbackHandler.setConfirmationMethod(SAML1Constants.CONF_SENDER_VOUCHES);
        callbackHandler.setIssuer("www.example.com");
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);
        
        WSSecSignatureSAML wsSign = new WSSecSignatureSAML();
        wsSign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document signedDoc = 
            wsSign.build(
                doc, null, samlAssertion, crypto, "16c73ab6-b892-458f-abf5-2f875f74882e",
                "security", secHeader
            );
        Element assertionElement = (Element) samlAssertion.getElement().cloneNode(true);
        assertionElement.removeChild(assertionElement.getFirstChild());
        secHeader.getSecurityHeader().appendChild(assertionElement);

        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML 1.1 Authn Assertion (sender vouches):");
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
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
    @org.junit.Test
    public void testDuplicatedSignedUsernameToken() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        WSSecUsernameToken usernameToken = new WSSecUsernameToken();
        usernameToken.setUserInfo("wss86", "security");
        Document createdDoc = usernameToken.build(doc, secHeader);
        
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        
        WSEncryptionPart encP =
            new WSEncryptionPart(
                "UsernameToken",
                WSConstants.WSSE_NS,
                "");
        builder.getParts().add(encP);
        
        builder.prepare(createdDoc, crypto, secHeader);
        
        List<javax.xml.crypto.dsig.Reference> referenceList = 
            builder.addReferencesToSign(builder.getParts(), secHeader);

        builder.computeSignature(referenceList, false, null);
        
        secHeader.getSecurityHeader().appendChild(
            usernameToken.getUsernameTokenElement().cloneNode(true)
        );
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed Timestamp");
            String outputString = 
                XMLUtils.PrettyDocumentToString(doc);
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
    @org.junit.Test
    public void testModifiedEncryptedDataStructure() throws Exception {
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setUserInfo("wss40");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        builder.setSymmetricEncAlgorithm(WSConstants.TRIPLE_DES);
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Crypto wssCrypto = CryptoFactory.getInstance("wss40.properties");
        Document encryptedDoc = builder.build(doc, wssCrypto, secHeader);

        Element body = WSSecurityUtil.findBodyElement(doc);
        Element encryptionMethod = 
            WSSecurityUtil.findElement(body, "EncryptionMethod", WSConstants.ENC_NS);
        encryptionMethod.setAttributeNS(null, "Algorithm", "http://new-algorithm");
        
        String outputString = 
            XMLUtils.PrettyDocumentToString(encryptedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        
        WSSecurityEngine newEngine = new WSSecurityEngine();
        try {
            newEngine.processSecurityHeader(doc, null, new KeystoreCallbackHandler(), wssCrypto);
            fail("Failure expected on a modified EncryptedData structure");
        } catch (WSSecurityException ex) {
            // expected
        }
    }
    
    /**
     * Test for when some EncryptedData CipherValue data is modified.
     */
    @org.junit.Test
    public void testModifiedEncryptedDataCipherValue() throws Exception {
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setUserInfo("wss40");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        builder.setSymmetricEncAlgorithm(WSConstants.TRIPLE_DES);
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Crypto wssCrypto = CryptoFactory.getInstance("wss40.properties");
        Document encryptedDoc = builder.build(doc, wssCrypto, secHeader);

        Element body = WSSecurityUtil.findBodyElement(doc);
        Element cipherValue = 
            WSSecurityUtil.findElement(body, "CipherValue", WSConstants.ENC_NS);
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
            XMLUtils.PrettyDocumentToString(encryptedDoc);
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
    @org.junit.Test
    public void testModifiedSecurityHeaderEncryptedDataCipherValue() throws Exception {
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setUserInfo("wss40");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        builder.setSymmetricEncAlgorithm(WSConstants.TRIPLE_DES);
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Crypto wssCrypto = CryptoFactory.getInstance("wss40.properties");
        
        WSSecTimestamp timestamp = new WSSecTimestamp();
        timestamp.setTimeToLive(300);
        timestamp.build(doc, secHeader);
        
        WSEncryptionPart encP =
            new WSEncryptionPart(
                "Timestamp",
                WSConstants.WSU_NS,
                "");
        builder.getParts().add(encP);
        
        Document encryptedDoc = builder.build(doc, wssCrypto, secHeader);

        Element securityHeader = 
            WSSecurityUtil.getSecurityHeader(encryptedDoc, "");
        Element encryptedTimestamp = 
            WSSecurityUtil.findElement(securityHeader, "EncryptedData", WSConstants.ENC_NS);
        Element cipherValue = 
            WSSecurityUtil.findElement(encryptedTimestamp, "CipherValue", WSConstants.ENC_NS);
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
            XMLUtils.PrettyDocumentToString(encryptedDoc);
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
    @org.junit.Test
    public void testModifiedEncryptedKeyCipherValue() throws Exception {
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setUserInfo("wss40");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        builder.setSymmetricEncAlgorithm(WSConstants.TRIPLE_DES);
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Crypto wssCrypto = CryptoFactory.getInstance("wss40.properties");
        Document encryptedDoc = builder.build(doc, wssCrypto, secHeader);

        Element encryptedKey = 
                WSSecurityUtil.findElement(doc.getDocumentElement(), "EncryptedKey", WSConstants.ENC_NS);
        Element cipherValue = 
            WSSecurityUtil.findElement(encryptedKey, "CipherValue", WSConstants.ENC_NS);
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
            XMLUtils.PrettyDocumentToString(encryptedDoc);
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
    @org.junit.Test
    public void testModifiedSignatureReference() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        WSSecTimestamp timestamp = new WSSecTimestamp();
        timestamp.setTimeToLive(300);
        Document createdDoc = timestamp.build(doc, secHeader);
        
        WSEncryptionPart encP =
            new WSEncryptionPart(
                "Timestamp",
                WSConstants.WSU_NS,
                "");
        builder.getParts().add(encP);
        
        Document signedDoc = builder.build(createdDoc, crypto, secHeader);
        
        // Modify the Created text of the Timestamp element
        Element timestampElement = timestamp.getElement();
        Element createdValue = 
            WSSecurityUtil.findElement(timestampElement, "Created", WSConstants.WSU_NS);
        DateFormat zulu = new XmlSchemaDateFormat();
        
        XMLGregorianCalendar createdCalendar = 
            WSSConfig.datatypeFactory.newXMLGregorianCalendar(createdValue.getTextContent());
        // Add 5 seconds
        Duration duration = WSSConfig.datatypeFactory.newDuration(5000L);
        createdCalendar.add(duration);
        Date createdDate = createdCalendar.toGregorianCalendar().getTime();
        createdValue.setTextContent(zulu.format(createdDate));
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
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
    @org.junit.Test
    public void testUntrustedSignature() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("wss40", "security");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Crypto wss40Crypto = CryptoFactory.getInstance("wss40.properties");
        Document signedDoc = builder.build(doc, wss40Crypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
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
    @org.junit.Test
    public void testModifiedSignature() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document signedDoc = builder.build(doc, crypto, secHeader);
        
        // Modify the Signature element
        Element signatureElement = builder.getSignatureElement();
        Node firstChild = signatureElement.getFirstChild();
        while (!(firstChild instanceof Element) && firstChild != null) {
            firstChild = signatureElement.getNextSibling();
        }
        ((Element)firstChild).setAttributeNS(null, "Id", "xyz");
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
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
    private List<WSSecurityEngineResult>  verify(Document doc) throws Exception {
        return secEngine.processSecurityHeader(doc, null, callbackHandler, crypto);
    }

}
