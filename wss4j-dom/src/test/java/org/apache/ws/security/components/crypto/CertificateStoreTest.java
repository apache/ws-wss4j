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

package org.apache.ws.security.components.crypto;

import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.common.KeystoreCallbackHandler;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.WSSecSignature;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;

import java.security.cert.X509Certificate;
import java.util.List;

import javax.security.auth.callback.CallbackHandler;

/**
 * This is a test for the CertificateStore Crypto instance. This class does not know anything
 * about Java KeyStores, but just wraps a list of trusted certificates.
 */
public class CertificateStoreTest extends org.junit.Assert {
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(CertificateStoreTest.class);
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private Crypto senderCrypto = CryptoFactory.getInstance("wss40.properties");
    private Crypto receiverCrypto = null;
    private CallbackHandler keystoreCallbackHandler = new KeystoreCallbackHandler();
    
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

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = sign.build(doc, senderCrypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        //
        // Verify the signature
        //
        List<WSSecurityEngineResult> results = verify(signedDoc, receiverCrypto);
        WSSecurityEngineResult result = 
            WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN);
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

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = sign.build(doc, senderCrypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        //
        // Verify the signature
        //
        // Turn off BSP spec compliance
        WSSecurityEngine newEngine = new WSSecurityEngine();
        WSSConfig config = WSSConfig.getNewInstance();
        config.setWsiBSPCompliant(false);
        newEngine.setWssConfig(config);
        List<WSSecurityEngineResult> results = 
            newEngine.processSecurityHeader(signedDoc, null, keystoreCallbackHandler, receiverCrypto);
        WSSecurityEngineResult result = 
            WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN);
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

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = sign.build(doc, senderCrypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        //
        // Verify the signature
        //
        List<WSSecurityEngineResult> results = verify(signedDoc, receiverCrypto);
        WSSecurityEngineResult result = 
            WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN);
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

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = sign.build(doc, senderCrypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        //
        // Verify the signature
        //
        List<WSSecurityEngineResult> results = verify(signedDoc, receiverCrypto);
        WSSecurityEngineResult result = 
            WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN);
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

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = sign.build(doc, senderCrypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        //
        // Verify the signature
        //
        List<WSSecurityEngineResult> results = verify(signedDoc, receiverCrypto);
        WSSecurityEngineResult result = 
            WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN);
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

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = sign.build(doc, CryptoFactory.getInstance(), secHeader);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
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
    private List<WSSecurityEngineResult> 
    verify(Document doc, Crypto crypto) throws WSSecurityException {
        List<WSSecurityEngineResult> results = secEngine.processSecurityHeader(
            doc, null, keystoreCallbackHandler, crypto
        );
        if (LOG.isDebugEnabled()) {
            LOG.debug("Verfied and decrypted message:");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        return results;
    }

    
}
