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

import java.util.ArrayList;
import java.util.List;

import javax.security.auth.callback.CallbackHandler;

import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.common.CustomHandler;
import org.apache.ws.security.common.KeystoreCallbackHandler;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.message.token.Reference;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.str.STRParser.REFERENCE_TYPE;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;


/**
 * A set of test-cases for signing and verifying SOAP requests.
 * 
 * @author Davanum Srinivas (dims@yahoo.com)
 * @author Werner Dittmann (Werner.Dittmann@siemens.com)
 */
public class SignatureTest extends org.junit.Assert {
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(SignatureTest.class);
    
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private CallbackHandler callbackHandler = new KeystoreCallbackHandler();
    private Crypto crypto = null;
    
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
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
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
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
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
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        // Turn off BSP spec compliance
        WSSecurityEngine newEngine = new WSSecurityEngine();
        WSSConfig config = WSSConfig.getNewInstance();
        config.setWsiBSPCompliant(false);
        newEngine.setWssConfig(config);
        newEngine.processSecurityHeader(doc, null, null, crypto);
        
        // Now turn on BSP spec compliance
        config.setWsiBSPCompliant(true);
        newEngine.setWssConfig(config);
        try {
            newEngine.processSecurityHeader(doc, null, null, crypto);
            fail("Failure expected on a bad c14n algorithm");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getMessage().contains("bad canonicalization algorithm"));
        }
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
        wssConfig.setWsiBSPCompliant(true);
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
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
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
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
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
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
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
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        // Turn off BSP spec compliance
        WSSecurityEngine newEngine = new WSSecurityEngine();
        WSSConfig config = WSSConfig.getNewInstance();
        config.setWsiBSPCompliant(false);
        newEngine.setWssConfig(config);
        List<WSSecurityEngineResult> results = newEngine.processSecurityHeader(doc, null, null, crypto);
        
        WSSecurityEngineResult actionResult =
                WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN);
        assertNotNull(actionResult.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE));
        assertNotNull(actionResult.get(WSSecurityEngineResult.TAG_X509_REFERENCE_TYPE));
        REFERENCE_TYPE referenceType = 
            (REFERENCE_TYPE)actionResult.get(WSSecurityEngineResult.TAG_X509_REFERENCE_TYPE);
        assertTrue(referenceType == REFERENCE_TYPE.KEY_IDENTIFIER);
        
        // Now turn on BSP spec compliance
        config.setWsiBSPCompliant(true);
        newEngine.setWssConfig(config);
        try {
            newEngine.processSecurityHeader(doc, null, null, crypto);
            fail("Failure expected on a bad ValueType attribute");
        } catch (WSSecurityException ex) {
            // expected
        }
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
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
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
        
        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        WSEncryptionPart encP =
            new WSEncryptionPart(
                "Timestamp",
                WSConstants.WSU_NS,
                "");
        parts.add(encP);
        builder.setParts(parts);
        
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
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
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
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
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
        final int action = WSConstants.SIGN;
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
        
        final java.util.List<Integer> actions = new java.util.ArrayList<Integer>();
        actions.add(Integer.valueOf(action));
        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        handler.send(
            action, 
            doc, 
            reqData, 
            actions,
            true
        );
        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed message:");
            LOG.debug(outputString);
        }
        assertTrue(
            outputString.indexOf("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256") != -1
        );
        assertTrue(
            outputString.indexOf("http://www.w3.org/2001/04/xmlenc#sha256") != -1
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
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
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
        
        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        WSEncryptionPart encP =
            new WSEncryptionPart(
                "Timestamp",
                WSConstants.WSU_NS,
                "");
        parts.add(encP);
        
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setParts(parts);
        
        builder.prepare(createdDoc, crypto, secHeader);
        
        List<javax.xml.crypto.dsig.Reference> referenceList = 
            builder.addReferencesToSign(parts, secHeader);

        builder.computeSignature(referenceList, false, null);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
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
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
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
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
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
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
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
        final int action = WSConstants.SIGN | WSConstants.TS;
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
        
        final java.util.List<Integer> actions = new java.util.ArrayList<Integer>();
        actions.add(Integer.valueOf(WSConstants.SIGN));
        actions.add(Integer.valueOf(WSConstants.TS));
        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        handler.send(
            action, 
            doc, 
            reqData, 
            actions,
            true
        );
        String outputString = 
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed message:");
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(doc);
        assertTrue(handler.checkResults(results, actions));
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
