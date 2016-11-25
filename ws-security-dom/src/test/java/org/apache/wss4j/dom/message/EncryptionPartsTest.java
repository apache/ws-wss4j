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
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.common.KeystoreCallbackHandler;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.security.auth.callback.CallbackHandler;
import javax.xml.namespace.QName;

import java.util.List;

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
            "       <foo:with-attributes some-attribute=\"3\">baz</foo:with-attributes>" +
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

    @org.junit.AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }

    public EncryptionPartsTest() throws Exception {
        crypto = CryptoFactory.getInstance();
        WSSConfig.init();
    }

    /**
     * Test encrypting a custom SOAP header
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testSOAPHeader() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        
        WSSecEncrypt encrypt = new WSSecEncrypt(secHeader);
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        WSEncryptionPart encP =
            new WSEncryptionPart(
                "foobar",
                "urn:foo.bar",
                "");
        encrypt.getParts().add(encP);

        Document encryptedDoc = encrypt.build(doc, crypto);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }

        WSHandlerResult results = verify(encryptedDoc);

        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.ENCR).get(0);
        assertTrue(actionResult != null);
        assertFalse(actionResult.isEmpty());
        final List<WSDataRef> refs =
            (List<WSDataRef>) actionResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);

        assertEquals(WSConstants.KEYTRANSPORT_RSAOAEP,
                actionResult.get(WSSecurityEngineResult.TAG_ENCRYPTED_KEY_TRANSPORT_METHOD));

        WSDataRef wsDataRef = refs.get(0);
        String xpath = wsDataRef.getXpath();
        assertEquals("/soapenv:Envelope/soapenv:Header/foo:foobar", xpath);
        assertEquals(WSConstants.AES_128, wsDataRef.getAlgorithm());
        QName expectedQName = new QName("urn:foo.bar", "foobar");
        assertEquals(expectedQName, wsDataRef.getName());

        Element encryptedElement = wsDataRef.getEncryptedElement();
        assertNotNull(encryptedElement);
        assertEquals(WSConstants.ENC_NS, encryptedElement.getNamespaceURI());
    }

    @Test
    public void testOptionalSOAPHeaderPresent() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        
        WSSecEncrypt encrypt = new WSSecEncrypt(secHeader);
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        WSEncryptionPart encP =
            new WSEncryptionPart(
                "foobar",
                "urn:foo.bar",
                "");
        encP.setRequired(false);
        encrypt.getParts().add(encP);
        String soapNamespace = WSSecurityUtil.getSOAPNamespace(doc.getDocumentElement());
        encP =
            new WSEncryptionPart(
                WSConstants.ELEM_BODY,
                soapNamespace,
                "Content"
            );
        encrypt.getParts().add(encP);

        Document encryptedDoc = encrypt.build(doc, crypto);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }

        verify(encryptedDoc);
    }

    @Test
    public void testOptionalSOAPHeaderNotPresent() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        
        WSSecEncrypt encrypt = new WSSecEncrypt(secHeader);
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        WSEncryptionPart encP =
            new WSEncryptionPart(
                "foobar",
                "urn:foo.bar",
                "");
        encP.setRequired(false);
        encrypt.getParts().add(encP);
        String soapNamespace = WSSecurityUtil.getSOAPNamespace(doc.getDocumentElement());
        encP =
            new WSEncryptionPart(
                WSConstants.ELEM_BODY,
                soapNamespace,
                "Content"
            );
        encrypt.getParts().add(encP);

        Document encryptedDoc = encrypt.build(doc, crypto);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }

        verify(encryptedDoc);
    }

    @Test
    public void testRequiredSOAPHeaderNotPresent() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        
        WSSecEncrypt encrypt = new WSSecEncrypt(secHeader);
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        WSEncryptionPart encP =
            new WSEncryptionPart(
                "foobar",
                "urn:foo.bar",
                "");
        encrypt.getParts().add(encP);
        String soapNamespace = WSSecurityUtil.getSOAPNamespace(doc.getDocumentElement());
        encP =
            new WSEncryptionPart(
                WSConstants.ELEM_BODY,
                soapNamespace,
                "Content"
            );
        encrypt.getParts().add(encP);

        try {
            encrypt.build(doc, crypto);
            fail("Failure expected on not encrypting a required element");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.FAILURE);
        }
    }


    /**
     * Test encrypting a custom SOAP header using wsse11:EncryptedHeader
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testSOAPEncryptedHeader() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        
        WSSecEncrypt encrypt = new WSSecEncrypt(secHeader);
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        WSEncryptionPart encP =
            new WSEncryptionPart(
                "foobar",
                "urn:foo.bar",
                "Header");
        encrypt.getParts().add(encP);

        Document encryptedDoc = encrypt.build(doc, crypto);

        String outputString =
            XMLUtils.prettyDocumentToString(encryptedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains("wsse11:EncryptedHeader"));
        assertFalse(outputString.contains("foo:foobar"));

        WSHandlerResult results = verify(encryptedDoc);

        WSSecurityEngineResult actionResult =
                results.getActionResults().get(WSConstants.ENCR).get(0);
        assertTrue(actionResult != null);
        assertFalse(actionResult.isEmpty());
        final List<WSDataRef> refs =
            (List<WSDataRef>) actionResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);

        assertEquals(WSConstants.KEYTRANSPORT_RSAOAEP,
                actionResult.get(WSSecurityEngineResult.TAG_ENCRYPTED_KEY_TRANSPORT_METHOD));

        WSDataRef wsDataRef = refs.get(0);
        String xpath = wsDataRef.getXpath();
        assertEquals("/soapenv:Envelope/soapenv:Header/foo:foobar", xpath);
    }

    /**
     * Test encrypting a custom SOAP header using wsse11:EncryptedHeader
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testSOAPEncryptedHeaderWithAttributes() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        
        WSSecEncrypt encrypt = new WSSecEncrypt(secHeader);
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        WSEncryptionPart encP =
            new WSEncryptionPart(
                "with-attributes",
                "urn:foo.bar",
                "Header");
        encrypt.getParts().add(encP);

        Document encryptedDoc = encrypt.build(doc, crypto);

        String outputString =
            XMLUtils.prettyDocumentToString(encryptedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains("wsse11:EncryptedHeader"));
        assertFalse(outputString.contains("foo:with-attributes"));

        WSHandlerResult results = verify(encryptedDoc);

        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.ENCR).get(0);
        assertTrue(actionResult != null);
        assertFalse(actionResult.isEmpty());
        final List<WSDataRef> refs =
            (List<WSDataRef>) actionResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);

        assertEquals(WSConstants.KEYTRANSPORT_RSAOAEP,
            actionResult.get(WSSecurityEngineResult.TAG_ENCRYPTED_KEY_TRANSPORT_METHOD));

        WSDataRef wsDataRef = refs.get(0);
        String xpath = wsDataRef.getXpath();
        assertEquals("/soapenv:Envelope/soapenv:Header/foo:with-attributes", xpath);
    }

    /**
     * Test encrypting a custom SOAP header with a bad localname
     */
    @Test
    public void testBadLocalname() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        
        WSSecEncrypt encrypt = new WSSecEncrypt(secHeader);
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        WSEncryptionPart encP =
            new WSEncryptionPart(
                "foobar2",
                "urn:foo.bar",
                "");
        encrypt.getParts().add(encP);

        try {
            encrypt.build(doc, crypto);
            fail("Failure expected on a bad localname");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.FAILURE);
        }
    }


    /**
     * Test encrypting a custom SOAP header with a bad namespace
     */
    @Test
    public void testBadNamespace() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        
        WSSecEncrypt encrypt = new WSSecEncrypt(secHeader);
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        WSEncryptionPart encP =
            new WSEncryptionPart(
                "foobar",
                "urn:foo.bar2",
                "");
        encrypt.getParts().add(encP);

        try {
            encrypt.build(doc, crypto);
            fail("Failure expected on a bad namespace");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.FAILURE);
        }
    }


    /**
     * Test encrypting a custom SOAP header and the SOAP body
     */
    @Test
    public void testSOAPHeaderAndBody() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        SOAPConstants soapConstants =
            WSSecurityUtil.getSOAPConstants(doc.getDocumentElement());
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        
        WSSecEncrypt encrypt = new WSSecEncrypt(secHeader);
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);


        WSEncryptionPart encP =
            new WSEncryptionPart(
                soapConstants.getBodyQName().getLocalPart(),    // define the body
                soapConstants.getEnvelopeURI(),
                "");
        encrypt.getParts().add(encP);
        WSEncryptionPart encP2 =
            new WSEncryptionPart(
                "foobar",
                "urn:foo.bar",
                "");
        encrypt.getParts().add(encP2);

        Document encryptedDoc = encrypt.build(doc, crypto);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }

        WSHandlerResult results = verify(encryptedDoc);

        QName fooName = new QName("urn:foo.bar", "foobar");
        QName bodyName = new QName(soapConstants.getEnvelopeURI(), "Body");
        QName headerName = new QName(soapConstants.getEnvelopeURI(), "Header");

        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.ENCR).get(0);
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
    public void testEncryptionPartDOMElement() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        SOAPConstants soapConstants =
            WSSecurityUtil.getSOAPConstants(doc.getDocumentElement());
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        
        WSSecEncrypt encrypt = new WSSecEncrypt(secHeader);
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        // Give wrong names to make sure it's picking up the element
        WSEncryptionPart encP =
            new WSEncryptionPart(
                "Incorrect Localname",
                "Incorrect N/S",
                "");
        Element bodyElement = WSSecurityUtil.findBodyElement(doc);
        assertTrue(bodyElement != null && "Body".equals(bodyElement.getLocalName()));
        encP.setElement(bodyElement);
        encrypt.getParts().add(encP);

        Document encryptedDoc = encrypt.build(doc, crypto);

        String outputString =
            XMLUtils.prettyDocumentToString(encryptedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        assertTrue(!outputString.contains("testMethod"));
        WSHandlerResult results = verify(encryptedDoc);

        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.ENCR).get(0);
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
     * Test encrypting two SOAP Body elements with the same QName.
     */
    @Test
    public void testMultipleElements() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG_MULTIPLE);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        
        WSSecEncrypt encrypt = new WSSecEncrypt(secHeader);
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        WSEncryptionPart encP =
            new WSEncryptionPart(
                "testMethod",
                "http://axis/service/security/test6/LogTestService8",
                "");
        encrypt.getParts().add(encP);

        Document encryptedDoc = encrypt.build(doc, crypto);

        String outputString =
            XMLUtils.prettyDocumentToString(encryptedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        assertFalse(outputString.contains("testMethod"));

        verify(encryptedDoc);

        outputString =
            XMLUtils.prettyDocumentToString(encryptedDoc);
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
    private WSHandlerResult verify(Document doc) throws Exception {
        WSHandlerResult results =
            secEngine.processSecurityHeader(doc, null, callbackHandler, null, crypto);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Verified and decrypted message:");
            String outputString =
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        return results;
    }

}
