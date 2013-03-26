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

import org.apache.wss4j.dom.SOAPConstants;
import org.apache.wss4j.dom.WSDataRef;
import org.apache.wss4j.dom.WSEncryptionPart;
import org.apache.wss4j.dom.WSSConfig;
import org.apache.wss4j.dom.WSSecurityEngine;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSSecurityEngineResult;
import org.apache.wss4j.dom.common.KeystoreCallbackHandler;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.security.auth.callback.CallbackHandler;
import javax.xml.namespace.QName;

import java.util.List;
import java.util.ArrayList;

/**
 * This is some unit tests for encryption using encryption using parts. Note that the "soapMsg" below
 * has a custom header added.
 */
public class EncryptionPartsTest extends org.junit.Assert {
    private static final org.slf4j.Logger LOG = 
        org.slf4j.LoggerFactory.getLogger(EncryptionPartsTest.class);
    private static final String SOAPMSG = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
            "<soapenv:Envelope xmlns:foo=\"urn:foo.bar\" xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" +
            "   <soapenv:Header>" +
            "       <foo:bar1>baz1</foo:bar1>" + 
            "       <foo:foobar>baz</foo:foobar>" + 
            "       <foo:bar2>baz2</foo:bar2>" +
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
    private CallbackHandler callbackHandler = new KeystoreCallbackHandler();
    private Crypto crypto = null;
    
    public EncryptionPartsTest() throws Exception {
        crypto = CryptoFactory.getInstance();
        WSSConfig.init();
    }

    /**
     * Test encrypting a custom SOAP header
     */
    @SuppressWarnings("unchecked")
    @org.junit.Test
    public void testSOAPHeader() throws Exception {
        WSSecEncrypt encrypt = new WSSecEncrypt();
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

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
        encrypt.setParts(parts);
        
        Document encryptedDoc = encrypt.build(doc, crypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(encryptedDoc);
        
        QName name = new QName("urn:foo.bar", "foobar");
        WSSecurityUtil.checkAllElementsProtected(results, WSConstants.ENCR, new QName[]{name});
        try {
            name = new QName("urn:foo.bar", "foobar2");
            WSSecurityUtil.checkAllElementsProtected(results, WSConstants.ENCR, new QName[]{name});
            fail("Failure expected on a wrong protected part");
        } catch (WSSecurityException ex) {
            // expected
        }
        try {
            name = new QName("urn:foo.bar", "foobar");
            WSSecurityUtil.checkAllElementsProtected(results, WSConstants.SIGN, new QName[]{name});
            fail("Failure expected on a wrong action");
        } catch (WSSecurityException ex) {
            // expected
        }
        
        WSSecurityEngineResult actionResult = 
            WSSecurityUtil.fetchActionResult(results, WSConstants.ENCR);
        assertTrue(actionResult != null);
        assertFalse(actionResult.isEmpty());
        final java.util.List<WSDataRef> refs =
            (java.util.List<WSDataRef>) actionResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
        
        assertEquals(WSConstants.KEYTRANSPORT_RSAOEP, 
                actionResult.get(WSSecurityEngineResult.TAG_ENCRYPTED_KEY_TRANSPORT_METHOD));
        
        WSDataRef wsDataRef = (WSDataRef)refs.get(0);
        String xpath = wsDataRef.getXpath();
        assertEquals("/soapenv:Envelope/soapenv:Header/foo:foobar", xpath);
        assertEquals(WSConstants.AES_128, wsDataRef.getAlgorithm());
    }
    
    
    /**
     * Test encrypting a custom SOAP header using wsse11:EncryptedHeader
     */
    @SuppressWarnings("unchecked")
    @org.junit.Test
    public void testSOAPEncryptedHeader() throws Exception {
        WSSecEncrypt encrypt = new WSSecEncrypt();
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        WSEncryptionPart encP =
            new WSEncryptionPart(
                "foobar",
                "urn:foo.bar",
                "Header");
        parts.add(encP);
        encrypt.setParts(parts);
        
        Document encryptedDoc = encrypt.build(doc, crypto, secHeader);
        
        String outputString = 
            XMLUtils.PrettyDocumentToString(encryptedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        assertTrue(outputString.indexOf("wsse11:EncryptedHeader") != -1);
        assertTrue(outputString.indexOf("foo:foobar") == -1);
        
        List<WSSecurityEngineResult> results = verify(encryptedDoc);
        
        WSSecurityEngineResult actionResult =
                WSSecurityUtil.fetchActionResult(results, WSConstants.ENCR);
        assertTrue(actionResult != null);
        assertFalse(actionResult.isEmpty());
        final java.util.List<WSDataRef> refs =
            (java.util.List<WSDataRef>) actionResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
        
        assertEquals(WSConstants.KEYTRANSPORT_RSAOEP, 
                actionResult.get(WSSecurityEngineResult.TAG_ENCRYPTED_KEY_TRANSPORT_METHOD));
        
        WSDataRef wsDataRef = (WSDataRef)refs.get(0);
        String xpath = wsDataRef.getXpath();
        assertEquals("/soapenv:Envelope/soapenv:Header/foo:foobar", xpath);
    }
    
    /**
     * Test encrypting a custom SOAP header with a bad localname
     */
    @org.junit.Test
    public void testBadLocalname() throws Exception {
        WSSecEncrypt encrypt = new WSSecEncrypt();
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

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
        encrypt.setParts(parts);
        
        try {
            encrypt.build(doc, crypto, secHeader);
            fail("Failure expected on a bad localname");
        } catch (WSSecurityException ex) {
            // expected
        }
    }
    
    
    /**
     * Test encrypting a custom SOAP header with a bad namespace
     */
    @org.junit.Test
    public void testBadNamespace() throws Exception {
        WSSecEncrypt encrypt = new WSSecEncrypt();
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

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
        encrypt.setParts(parts);
        
        try {
            encrypt.build(doc, crypto, secHeader);
            fail("Failure expected on a bad namespace");
        } catch (WSSecurityException ex) {
            // expected
        }
    }
    
    
    /**
     * Test encrypting a custom SOAP header and the SOAP body
     */
    @org.junit.Test
    public void testSOAPHeaderAndBody() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        SOAPConstants soapConstants = 
            WSSecurityUtil.getSOAPConstants(doc.getDocumentElement());
        WSSecEncrypt encrypt = new WSSecEncrypt();
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

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
        encrypt.setParts(parts);
        
        Document encryptedDoc = encrypt.build(doc, crypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(encryptedDoc);
        
        QName fooName = new QName("urn:foo.bar", "foobar");
        QName bodyName = new QName(soapConstants.getEnvelopeURI(), "Body");
        WSSecurityUtil.checkAllElementsProtected(results, WSConstants.ENCR, new QName[]{fooName});
        WSSecurityUtil.checkAllElementsProtected(results, WSConstants.ENCR, new QName[]{bodyName});
        WSSecurityUtil.checkAllElementsProtected(
            results, 
            WSConstants.ENCR, 
            new QName[]{bodyName, fooName}
        );
        WSSecurityUtil.checkAllElementsProtected(
            results, 
            WSConstants.ENCR, 
            new QName[]{fooName, bodyName}
        );
        try {
            WSSecurityUtil.checkAllElementsProtected(
                results, 
                WSConstants.SIGN, 
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
                WSConstants.ENCR, 
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
    public void testEncryptionPartDOMElement() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        SOAPConstants soapConstants = 
            WSSecurityUtil.getSOAPConstants(doc.getDocumentElement());
        WSSecEncrypt encrypt = new WSSecEncrypt();
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

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
        encrypt.setParts(parts);
        
        Document encryptedDoc = encrypt.build(doc, crypto, secHeader);
        
        String outputString = 
            XMLUtils.PrettyDocumentToString(encryptedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        assertTrue (!outputString.contains("testMethod"));
        List<WSSecurityEngineResult> results = verify(encryptedDoc);
        
        QName bodyName = new QName(soapConstants.getEnvelopeURI(), "Body");
        WSSecurityUtil.checkAllElementsProtected(results, WSConstants.ENCR, new QName[]{bodyName});
    }
    
    /**
     * Test encrypting two SOAP Body elements with the same QName.
     */
    @org.junit.Test
    public void testMultipleElements() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG_MULTIPLE);
        WSSecEncrypt encrypt = new WSSecEncrypt();
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        WSEncryptionPart encP =
            new WSEncryptionPart(
                "testMethod",
                "http://axis/service/security/test6/LogTestService8",
                "");
        parts.add(encP);
        encrypt.setParts(parts);
        
        Document encryptedDoc = encrypt.build(doc, crypto, secHeader);
        
        String outputString = 
            XMLUtils.PrettyDocumentToString(encryptedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        assertTrue(!outputString.contains("testMethod"));
        
        verify(encryptedDoc);
        
        outputString = 
            XMLUtils.PrettyDocumentToString(encryptedDoc);
        assertTrue(outputString.contains("asf1"));
        assertTrue(outputString.contains("asf2"));
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
            secEngine.processSecurityHeader(doc, null, callbackHandler, null, crypto);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Verified and decrypted message:");
            String outputString = 
                XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        return results;
    }

}
