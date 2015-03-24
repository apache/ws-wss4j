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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.security.auth.callback.CallbackHandler;

import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.token.Reference;
import org.apache.wss4j.common.token.SecurityTokenReference;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSSConfig;
import org.apache.wss4j.dom.WSSecurityEngine;
import org.apache.wss4j.dom.WSSecurityEngineResult;
import org.apache.wss4j.dom.common.CustomHandler;
import org.apache.wss4j.dom.common.KeystoreCallbackHandler;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.dom.handler.HandlerAction;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.dom.str.STRParser.REFERENCE_TYPE;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;


/**
 * A set of test-cases for signing and verifying SOAP requests.
 */
public class SignatureTest extends org.junit.Assert {
    private static final org.slf4j.Logger LOG = 
        org.slf4j.LoggerFactory.getLogger(SignatureTest.class);
    
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private CallbackHandler callbackHandler = new KeystoreCallbackHandler();
    private Crypto crypto = null;
    
    @org.junit.AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }
    
    public SignatureTest() throws Exception {
        WSSConfig.init();
        crypto = CryptoFactory.getInstance();
    }

    /**
     * The test uses the Issuer Serial key identifier type.
     * <p/>
     * 
     * @throws java.lang.Exception Thrown when there is any problem in signing or verification
     */
    @org.junit.Test
    public void testX509SignatureIS() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        LOG.info("Before Signing IS....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed message with IssuerSerial key identifier:");
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        LOG.info("After Signing IS....");
        List<WSSecurityEngineResult> results = verify(signedDoc);
        
        WSSecurityEngineResult actionResult =
                WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN);
        assertNotNull(actionResult.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE));
        assertNotNull(actionResult.get(WSSecurityEngineResult.TAG_X509_REFERENCE_TYPE));
        REFERENCE_TYPE referenceType = 
            (REFERENCE_TYPE)actionResult.get(WSSecurityEngineResult.TAG_X509_REFERENCE_TYPE);
        assertTrue(referenceType == REFERENCE_TYPE.ISSUER_SERIAL);
    }
    
    @org.junit.Test
    public void testX509SignatureISAttached() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        builder.setIncludeSignatureToken(true);
        LOG.info("Before Signing IS....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed message with IssuerSerial key identifier:");
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        LOG.info("After Signing IS....");
        List<WSSecurityEngineResult> results = verify(signedDoc);
        
        WSSecurityEngineResult actionResult =
                WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN);
        assertNotNull(actionResult.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE));
        assertNotNull(actionResult.get(WSSecurityEngineResult.TAG_X509_REFERENCE_TYPE));
        REFERENCE_TYPE referenceType = 
            (REFERENCE_TYPE)actionResult.get(WSSecurityEngineResult.TAG_X509_REFERENCE_TYPE);
        assertTrue(referenceType == REFERENCE_TYPE.ISSUER_SERIAL);
    }
    

    /**
     * Test that signs (twice) and verifies a WS-Security envelope.
     * <p/>
     * 
     * @throws java.lang.Exception Thrown when there is any problem in signing or verification
     */
    @org.junit.Test
    public void testDoubleX509SignatureIS() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, crypto, secHeader);
        Document signedDoc1 = builder.build(signedDoc, crypto, secHeader);
        verify(signedDoc1);
    }
    
    /**
     * Test that signs and verifies a WS-Security envelope
     * <p/>
     * 
     * @throws java.lang.Exception Thrown when there is any problem in signing or verification
     */
    @org.junit.Test
    public void testIssuerSerialSignature() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        LOG.info("Before Signing....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        verify(signedDoc);
    }
    
    /**
     * Test that signs and verifies a WS-Security envelope
     * <p/>
     * 
     * @throws java.lang.Exception Thrown when there is any problem in signing or verification
     */
    @org.junit.Test
    public void testSignatureInclusiveC14N() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setSigCanonicalization(WSConstants.C14N_OMIT_COMMENTS);
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        LOG.info("Before Signing....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        WSSecurityEngine newEngine = new WSSecurityEngine();
        try {
            newEngine.processSecurityHeader(doc, null, null, crypto);
            fail("Failure expected on a bad c14n algorithm");
        } catch (WSSecurityException ex) {
            // expected
        }
        
        RequestData data = new RequestData();
        data.setSigVerCrypto(crypto);
        List<BSPRule> ignoredRules = new ArrayList<>();
        ignoredRules.add(BSPRule.R5404);
        ignoredRules.add(BSPRule.R5406);
        data.setIgnoredBSPRules(ignoredRules);
        newEngine.processSecurityHeader(doc, "", data);
    }
    
    /**
     * Test that signs and verifies a WS-Security envelope
     * <p/>
     * 
     * @throws java.lang.Exception Thrown when there is any problem in signing or verification
     */
    @org.junit.Test
    public void testSignatureInclusivePrefixes() throws Exception {
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        wssConfig.setAddInclusivePrefixes(true);
        WSSecSignature builder = new WSSecSignature();
        builder.setWsConfig(wssConfig);
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        LOG.info("Before Signing....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        verify(signedDoc);
    }
    
    /**
     * Test that signs and verifies a WS-Security envelope
     * <p/>
     * 
     * @throws java.lang.Exception Thrown when there is any problem in signing or verification
     */
    @org.junit.Test
    public void testBSTSignature() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        LOG.info("Before Signing....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(signedDoc);
        
        WSSecurityEngineResult actionResult =
                WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN);
        assertNotNull(actionResult.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE));
        assertNotNull(actionResult.get(WSSecurityEngineResult.TAG_X509_REFERENCE_TYPE));
        REFERENCE_TYPE referenceType = 
            (REFERENCE_TYPE)actionResult.get(WSSecurityEngineResult.TAG_X509_REFERENCE_TYPE);
        assertTrue(referenceType == REFERENCE_TYPE.DIRECT_REF);
    }
    
    /**
     * Test that signs and verifies a WS-Security envelope
     * <p/>
     * 
     * @throws java.lang.Exception Thrown when there is any problem in signing or verification
     */
    @org.junit.Test
    public void testBSTPKIPathSignature() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("wss40", "security");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        builder.setUseSingleCertificate(false);
        LOG.info("Before Signing....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Crypto pkiCrypto = CryptoFactory.getInstance("wss40.properties");
        Document signedDoc = builder.build(doc, pkiCrypto, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("After PKI Signing....");
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        secEngine.processSecurityHeader(doc, null, callbackHandler, pkiCrypto, null);
    }
    
    /**
     * Test that signs and verifies a WS-Security envelope
     * <p/>
     * 
     * @throws java.lang.Exception Thrown when there is any problem in signing or verification
     */
    @org.junit.Test
    public void testX509Signature() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.X509_KEY_IDENTIFIER);
        LOG.info("Before Signing....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        WSSecurityEngine newEngine = new WSSecurityEngine();
        List<WSSecurityEngineResult> results = 
            newEngine.processSecurityHeader(doc, null, null, crypto);

        WSSecurityEngineResult actionResult =
                WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN);
        assertNotNull(actionResult.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE));
        assertNotNull(actionResult.get(WSSecurityEngineResult.TAG_X509_REFERENCE_TYPE));
        REFERENCE_TYPE referenceType = 
            (REFERENCE_TYPE)actionResult.get(WSSecurityEngineResult.TAG_X509_REFERENCE_TYPE);
        assertTrue(referenceType == REFERENCE_TYPE.KEY_IDENTIFIER);
    }
    
    /**
     * Test that signs and verifies a WS-Security envelope.
     * The test uses the ThumbprintSHA1 key identifier type. 
     * <p/>
     * 
     * @throws java.lang.Exception Thrown when there is any problem in signing or verification
     */
    @org.junit.Test
    public void testX509SignatureThumb() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
        LOG.info("Before Signing ThumbprintSHA1....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        Document signedDoc = builder.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed message with ThumbprintSHA1 key identifier:");
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        LOG.info("After Signing ThumbprintSHA1....");
        
        List<WSSecurityEngineResult> results = verify(signedDoc);
        
        WSSecurityEngineResult actionResult =
                WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN);
        assertNotNull(actionResult.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE));
        assertNotNull(actionResult.get(WSSecurityEngineResult.TAG_X509_REFERENCE_TYPE));
        REFERENCE_TYPE referenceType = 
            (REFERENCE_TYPE)actionResult.get(WSSecurityEngineResult.TAG_X509_REFERENCE_TYPE);
        assertTrue(referenceType == REFERENCE_TYPE.THUMBPRINT_SHA1);
    }

    @org.junit.Test
    public void testX509SignatureThumbAttached() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
        builder.setIncludeSignatureToken(true);
        LOG.info("Before Signing ThumbprintSHA1....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        Document signedDoc = builder.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed message with ThumbprintSHA1 key identifier:");
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        LOG.info("After Signing ThumbprintSHA1....");
        
        List<WSSecurityEngineResult> results = verify(signedDoc);
        
        WSSecurityEngineResult actionResult =
                WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN);
        assertNotNull(actionResult.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE));
        assertNotNull(actionResult.get(WSSecurityEngineResult.TAG_X509_REFERENCE_TYPE));
        REFERENCE_TYPE referenceType = 
            (REFERENCE_TYPE)actionResult.get(WSSecurityEngineResult.TAG_X509_REFERENCE_TYPE);
        assertTrue(referenceType == REFERENCE_TYPE.THUMBPRINT_SHA1);
    }
    
    /**
     * Test that signs (twice) and verifies a WS-Security envelope.
     * The test uses the ThumbprintSHA1 key identifier type.
     * <p/>
     * 
     * @throws java.lang.Exception Thrown when there is any problem in signing or verification
     */
    @org.junit.Test
    public void testDoubleX509SignatureThumb() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        Document signedDoc = builder.build(doc, crypto, secHeader);
        Document signedDoc1 = builder.build(signedDoc, crypto, secHeader);
        verify(signedDoc1);
    }
    
    
    /**
     * Test that signs and verifies a Timestamp. The request is then modified so that the
     * Timestamp has a default (WSU) namespace inserted. The signature validation should still
     * pass due to c14n (see WSS-181).
     * 
     * @throws java.lang.Exception Thrown when there is any problem in signing or verification
     */
    @org.junit.Test
    public void testValidModifiedSignature() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        LOG.info("Before Signing....");
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
        org.w3c.dom.Element secHeaderElement = secHeader.getSecurityHeader();
        org.w3c.dom.Node timestampNode = 
            secHeaderElement.getElementsByTagNameNS(WSConstants.WSU_NS, "Timestamp").item(0);
        ((org.w3c.dom.Element)timestampNode).setAttributeNS(
            WSConstants.XMLNS_NS, "xmlns", WSConstants.WSU_NS
        );
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        verify(signedDoc);
    }
    
    /**
     * Sign using a different digest algorithm (SHA-256).
     * <p/>
     * 
     * @throws java.lang.Exception Thrown when there is any problem in signing or verification
     */
    @org.junit.Test
    public void testX509SignatureSha256() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        builder.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        builder.setDigestAlgo("http://www.w3.org/2001/04/xmlenc#sha256");
        LOG.info("Before Signing IS....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed message with IssuerSerial key identifier:");
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        LOG.info("After Signing IS....");
        verify(signedDoc);
    }
    
    /**
     * A test for "SignatureAction does not set DigestAlgorithm on WSSecSignature instance"
     */
    @org.junit.Test
    public void
    testWSS170() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        reqData.setUsername("16c73ab6-b892-458f-abf5-2f875f74882e");
        java.util.Map<String, Object> config = new java.util.TreeMap<String, Object>();
        config.put(WSHandlerConstants.SIG_PROP_FILE, "crypto.properties");
        config.put("password", "security");
        config.put(
            WSHandlerConstants.SIG_ALGO, 
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
        );
        config.put(
            WSHandlerConstants.SIG_DIGEST_ALGO, 
            "http://www.w3.org/2001/04/xmlenc#sha256"
        );
        reqData.setMsgContext(config);
        
        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        HandlerAction action = new HandlerAction(WSConstants.SIGN);
        handler.send(
            doc, 
            reqData, 
            Collections.singletonList(action),
            true
        );
        String outputString = 
            XMLUtils.PrettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed message:");
            LOG.debug(outputString);
        }
        assertTrue(
                outputString.contains("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
        );
        assertTrue(
                outputString.contains("http://www.w3.org/2001/04/xmlenc#sha256")
        );
        
        verify(doc);
    }
    
    /**
     * This is a test for WSS-234 - 
     * "When a document contains a comment as its first child element, 
     * wss4j will not find the SOAP body." 
     */
    @org.junit.Test
    public void testWSS234() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        LOG.info("Before Signing....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, crypto, secHeader);
        
        // Add a comment node as the first node element
        org.w3c.dom.Node firstChild = signedDoc.getFirstChild();
        org.w3c.dom.Node newNode = signedDoc.removeChild(firstChild);
        org.w3c.dom.Node commentNode = signedDoc.createComment("This is a comment");
        signedDoc.appendChild(commentNode);
        signedDoc.appendChild(newNode);

        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        verify(signedDoc);
    }
    
    /**
     * Test that signs and verifies a Timestamp. The Signature element is appended to the security
     * header, and so appears after the Timestamp element.
     */
    @org.junit.Test
    public void testSignedTimestamp() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        WSSecTimestamp timestamp = new WSSecTimestamp();
        timestamp.setTimeToLive(300);
        Document createdDoc = timestamp.build(doc, secHeader);
        
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        
        WSEncryptionPart encP =
            new WSEncryptionPart(
                "Timestamp",
                WSConstants.WSU_NS,
                "");
        builder.getParts().add(encP);
        
        builder.prepare(createdDoc, crypto, secHeader);
        
        List<javax.xml.crypto.dsig.Reference> referenceList = 
            builder.addReferencesToSign(builder.getParts(), secHeader);

        builder.computeSignature(referenceList, false, null);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString = 
                XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        
        verify(doc);
    }
    
    /**
     * This is a test for WSS-283 - "ClassCastException when signing message with existing 
     * WSSE header containing Text as first child":
     * 
     * https://issues.apache.org/jira/browse/WSS-283
     */
    @org.junit.Test
    public void testWSS283() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        Element secHeaderElement = secHeader.insertSecurityHeader(doc);
        Node textNode = doc.createTextNode("This is a text node");
        secHeaderElement.appendChild(textNode);
        Document signedDoc = builder.build(doc, crypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed message with text node:");
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        verify(signedDoc);
    }
    
    /**
     * Create a signature that uses a custom SecurityTokenReference.
     */
    @org.junit.Test
    public void testCustomSTR() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        LOG.info("Before Signing IS....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        SecurityTokenReference secRef = new SecurityTokenReference(doc);
        Reference ref = new Reference(doc);
        ref.setURI("custom-uri");
        secRef.setReference(ref);
        builder.setSecurityTokenReference(secRef);
        
        Document signedDoc = builder.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
    }
    
    /**
     * The test uses the Issuer Serial key identifier type.
     * <p/>
     * 
     * @throws java.lang.Exception Thrown when there is any problem in signing or verification
     */
    @org.junit.Test
    public void testX509SignatureDefaultPassword() throws Exception {
        Crypto passwordCrypto = CryptoFactory.getInstance("alice.properties");
        
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo(passwordCrypto.getDefaultX509Identifier(), null);
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        LOG.info("Before Signing IS....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, passwordCrypto, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed message with IssuerSerial key identifier:");
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        LOG.info("After Signing IS....");
        WSSecurityEngine newEngine = new WSSecurityEngine();
        newEngine.processSecurityHeader(doc, null, null, passwordCrypto);
    }
    
    /**
     * A test for "There is an issue with the position of the <Timestamp> element in the
     * <Security> header when using WSS4J calling .NET Web Services with WS-Security."
     */
    @org.junit.Test
    public void
    testWSS231() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        reqData.setUsername("16c73ab6-b892-458f-abf5-2f875f74882e");
        
        java.util.Map<String, Object> config = new java.util.TreeMap<String, Object>();
        config.put(WSHandlerConstants.SIG_PROP_FILE, "crypto.properties");
        config.put("password", "security");
        config.put(
            WSHandlerConstants.SIGNATURE_PARTS, "{}{" + WSConstants.WSU_NS + "}Timestamp"
        );
        reqData.setMsgContext(config);
        
        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        List<HandlerAction> actions = new ArrayList<>();
        actions.add(new HandlerAction(WSConstants.SIGN));
        actions.add(new HandlerAction(WSConstants.TS));
        handler.send(
            doc, 
            reqData, 
            actions,
            true
        );
        String outputString = 
            XMLUtils.PrettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed message:");
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(doc);
        
        List<Integer> receivedActions = new ArrayList<>();
        receivedActions.add(WSConstants.SIGN);
        receivedActions.add(WSConstants.TS);
        assertTrue(handler.checkResults(results, receivedActions));
    }
    
    @org.junit.Test
    public void
    testSignatureEncryptTimestampOrder() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        reqData.setUsername("16c73ab6-b892-458f-abf5-2f875f74882e");
        
        java.util.Map<String, Object> config = new java.util.TreeMap<String, Object>();
        config.put(WSHandlerConstants.SIG_PROP_FILE, "crypto.properties");
        config.put(WSHandlerConstants.ENC_PROP_FILE, "crypto.properties");
        config.put("password", "security");
        config.put(
            WSHandlerConstants.SIGNATURE_PARTS, "{}{" + WSConstants.WSU_NS + "}Timestamp"
        );
        reqData.setMsgContext(config);
        
        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        List<HandlerAction> actions = new ArrayList<>();
        actions.add(new HandlerAction(WSConstants.SIGN));
        actions.add(new HandlerAction(WSConstants.ENCR));
        actions.add(new HandlerAction(WSConstants.TS));
        handler.send(
            doc, 
            reqData, 
            actions,
            true
        );
        String outputString = 
            XMLUtils.PrettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed message:");
            LOG.debug(outputString);
        }
    }
    
    @org.junit.Test
    public void
    testEncryptSignatureTimestampOrder() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        reqData.setUsername("16c73ab6-b892-458f-abf5-2f875f74882e");
        
        java.util.Map<String, Object> config = new java.util.TreeMap<String, Object>();
        config.put(WSHandlerConstants.SIG_PROP_FILE, "crypto.properties");
        config.put(WSHandlerConstants.ENC_PROP_FILE, "crypto.properties");
        config.put("password", "security");
        config.put(
            WSHandlerConstants.SIGNATURE_PARTS, "{}{" + WSConstants.WSU_NS + "}Timestamp"
        );
        reqData.setMsgContext(config);
        
        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        List<HandlerAction> actions = new ArrayList<>();
        actions.add(new HandlerAction(WSConstants.ENCR));
        actions.add(new HandlerAction(WSConstants.SIGN));
        actions.add(new HandlerAction(WSConstants.TS));
        handler.send(
            doc, 
            reqData, 
            actions,
            true
        );
        String outputString = 
            XMLUtils.PrettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed message:");
            LOG.debug(outputString);
        }
    }
    
    @org.junit.Test
    public void testWSHandlerSignatureCanonicalization() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        reqData.setUsername("16c73ab6-b892-458f-abf5-2f875f74882e");
        
        java.util.Map<String, Object> config = new java.util.TreeMap<String, Object>();
        config.put(WSHandlerConstants.SIG_PROP_FILE, "crypto.properties");
        config.put(WSHandlerConstants.SIG_C14N_ALGO, WSConstants.C14N_WITH_COMMENTS);
        config.put("password", "security");
        reqData.setMsgContext(config);
        
        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        HandlerAction action = new HandlerAction(WSConstants.SIGN);
        handler.send(
            doc, 
            reqData, 
            Collections.singletonList(action),
            true
        );
        String outputString = 
            XMLUtils.PrettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed message:");
            LOG.debug(outputString);
        }
        
        RequestData data = new RequestData();
        data.setWssConfig(WSSConfig.getNewInstance());
        data.setSigVerCrypto(crypto);
        
        List<BSPRule> disabledRules = new ArrayList<>();
        disabledRules.add(BSPRule.R5404);
        disabledRules.add(BSPRule.R5406);
        data.setIgnoredBSPRules(disabledRules);
        
        WSSecurityEngine newSecEngine = new WSSecurityEngine();
        List<WSSecurityEngineResult> results = 
            newSecEngine.processSecurityHeader(doc, "", data);
        assertTrue(handler.checkResults(results, Collections.singletonList(WSConstants.SIGN)));
    }
    
    @org.junit.Test
    public void testCommentInSOAPBody() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        LOG.info("Before Signing....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, crypto, secHeader);
        
        // Add a comment node
        Element body = WSSecurityUtil.findBodyElement(signedDoc);
        org.w3c.dom.Node commentNode = signedDoc.createComment("This is a comment");
        body.getFirstChild().appendChild(commentNode);

        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        verify(signedDoc);
    }
    

    /**
     * Verifies the soap envelope.
     * This method verifies all the signature generated. 
     * 
     * @param env soap envelope
     * @throws java.lang.Exception Thrown when there is a problem in verification
     */
    private List<WSSecurityEngineResult> verify(Document doc) throws Exception {
        return secEngine.processSecurityHeader(doc, null, null, crypto);
    }

}
