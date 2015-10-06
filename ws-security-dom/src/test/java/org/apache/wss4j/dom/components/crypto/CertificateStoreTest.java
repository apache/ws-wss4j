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

package org.apache.wss4j.dom.components.crypto;

import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.common.KeystoreCallbackHandler;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.crypto.CertificateStore;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecSignature;
import org.w3c.dom.Document;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import javax.security.auth.callback.CallbackHandler;

/**
 * This is a test for the CertificateStore Crypto instance. This class does not know anything
 * about Java KeyStores, but just wraps a list of trusted certificates.
 */
public class CertificateStoreTest extends org.junit.Assert {
    private static final org.slf4j.Logger LOG = 
        org.slf4j.LoggerFactory.getLogger(CertificateStoreTest.class);
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private Crypto senderCrypto = CryptoFactory.getInstance("wss40.properties");
    private Crypto receiverCrypto = null;
    private CallbackHandler keystoreCallbackHandler = new KeystoreCallbackHandler();
    
    @org.junit.AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }
    
    public CertificateStoreTest() throws Exception {
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("wss40");
        X509Certificate[] certs = senderCrypto.getX509Certificates(cryptoType);
        receiverCrypto = new CertificateStore(certs);
        WSSConfig.init();
    }

    /**
     * Test signing a SOAP message using a BST.
     */
    @org.junit.Test
    public void testSignatureDirectReference() throws Exception {
        WSSecSignature sign = new WSSecSignature();
        sign.setUserInfo("wss40", "security");
        sign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        Document signedDoc = sign.build(doc, senderCrypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        //
        // Verify the signature
        //
        WSHandlerResult results = verify(signedDoc, receiverCrypto);
        List<WSSecurityEngineResult> signatureResults = 
            results.getActionResults().get(WSConstants.SIGN);
        WSSecurityEngineResult result = signatureResults.get(0);
        X509Certificate cert = 
            (X509Certificate)result.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE);
        assertTrue (cert != null);
    }
    
    /**
     * Test signing a SOAP message using an X.509 Key Identifier.
     */
    @org.junit.Test
    public void testSignatureX509() throws Exception {
        WSSecSignature sign = new WSSecSignature();
        sign.setUserInfo("wss40", "security");
        sign.setKeyIdentifierType(WSConstants.X509_KEY_IDENTIFIER);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        Document signedDoc = sign.build(doc, senderCrypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        //
        // Verify the signature
        //
        WSSecurityEngine newEngine = new WSSecurityEngine();
        RequestData data = new RequestData();
        data.setCallbackHandler(keystoreCallbackHandler);
        data.setSigVerCrypto(receiverCrypto);
        data.setIgnoredBSPRules(Collections.singletonList(BSPRule.R3063));
        WSHandlerResult results = newEngine.processSecurityHeader(signedDoc, data);
        
        List<WSSecurityEngineResult> signatureResults = 
            results.getActionResults().get(WSConstants.SIGN);
        WSSecurityEngineResult result = signatureResults.get(0);
        X509Certificate cert = 
            (X509Certificate)result.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE);
        assertTrue (cert != null);
    }
    
    /**
     * Test signing a SOAP message using Issuer Serial.
     */
    @org.junit.Test
    public void testSignatureIssuerSerial() throws Exception {
        WSSecSignature sign = new WSSecSignature();
        sign.setUserInfo("wss40", "security");
        sign.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        Document signedDoc = sign.build(doc, senderCrypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        //
        // Verify the signature
        //
        WSHandlerResult results = verify(signedDoc, receiverCrypto);
        
        List<WSSecurityEngineResult> signatureResults = 
            results.getActionResults().get(WSConstants.SIGN);
        WSSecurityEngineResult result = signatureResults.get(0);
        X509Certificate cert = 
            (X509Certificate)result.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE);
        assertTrue (cert != null);
    }
    
    /**
     * Test signing a SOAP message using a Thumbprint
     */
    @org.junit.Test
    public void testSignatureThumbprint() throws Exception {
        WSSecSignature sign = new WSSecSignature();
        sign.setUserInfo("wss40", "security");
        sign.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        Document signedDoc = sign.build(doc, senderCrypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        //
        // Verify the signature
        //
        WSHandlerResult results = verify(signedDoc, receiverCrypto);
        List<WSSecurityEngineResult> signatureResults = 
            results.getActionResults().get(WSConstants.SIGN);
        WSSecurityEngineResult result = signatureResults.get(0);
        
        X509Certificate cert = 
            (X509Certificate)result.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE);
        assertTrue (cert != null);
    }
    
    /**
     * Test signing a SOAP message using a SKI Key Identifier
     */
    @org.junit.Test
    public void testSignatureSKI() throws Exception {
        WSSecSignature sign = new WSSecSignature();
        sign.setUserInfo("wss40", "security");
        sign.setKeyIdentifierType(WSConstants.SKI_KEY_IDENTIFIER);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        Document signedDoc = sign.build(doc, senderCrypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        //
        // Verify the signature
        //
        WSHandlerResult results = verify(signedDoc, receiverCrypto);
        
        List<WSSecurityEngineResult> signatureResults = 
            results.getActionResults().get(WSConstants.SIGN);
        WSSecurityEngineResult result = signatureResults.get(0);
        X509Certificate cert = 
            (X509Certificate)result.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE);
        assertTrue (cert != null);
    }
    
    /**
     * Test signing a SOAP message using a BST. The certificate is not known to the
     * CertificateStore and so should throw an exception.
     */
    @org.junit.Test
    public void testSignatureDirectReferenceUntrusted() throws Exception {
        WSSecSignature sign = new WSSecSignature();
        sign.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        sign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        Document signedDoc = sign.build(doc, CryptoFactory.getInstance(), secHeader);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        //
        // Verify the signature
        //
        try {
            verify(signedDoc, receiverCrypto);
            fail("Failure expected on an unknown certificate");
        } catch (WSSecurityException ex) {
            // expected
        }
    }
    
    /**
     * Verifies the soap envelope
     * <p/>
     * 
     * @param doc 
     * @throws Exception Thrown when there is a problem in verification
     */
    private WSHandlerResult verify(Document doc, Crypto crypto) throws Exception {
        WSHandlerResult results = secEngine.processSecurityHeader(
            doc, null, keystoreCallbackHandler, crypto
        );
        if (LOG.isDebugEnabled()) {
            LOG.debug("Verfied and decrypted message:");
            String outputString = 
                XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        return results;
    }

    
}
