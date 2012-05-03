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

import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.common.CustomHandler;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * This is a test for WSS-40. Essentially it just tests that a message is signed using a
 * keyEntry from one keystore, and verified at the other end with a keystore with just the
 * CA cert in it.
 * 
 * http://issues.apache.org/jira/browse/WSS-40
 * 
 * Generate the CA keys/certs + export the CA cert to a keystore
 * 
 * openssl req -x509 -newkey rsa:1024 -keyout wss40CAKey.pem -out wss40CA.pem 
 * -config ca.config -days 3650
 * openssl x509 -outform DER -in wss40CA.pem -out wss40CA.crt
 * keytool -import -file wss40CA.crt -alias wss40CA -keystore wss40CA.jks
 * 
 * Generate the client keypair, make a csr, sign it with the CA key
 * 
 * keytool -genkey -validity 3650 -alias wss40 -keyalg RSA -keystore wss40.jks 
 * -dname "CN=Colm,OU=WSS4J,O=Apache,L=Dublin,ST=Leinster,C=IE"
 * keytool -certreq -alias wss40 -keystore wss40.jks -file wss40.cer
 * openssl ca -config ca.config -policy policy_anything -days 3650 -out wss40.pem 
 * -infiles wss40.cer
 * openssl x509 -outform DER -in wss40.pem -out wss40.crt
 * 
 * Import the CA cert into wss40.jks and import the new signed certificate
 * 
 * keytool -import -file wss40CA.crt -alias wss40CA -keystore wss40.jks
 * keytool -import -file wss40.crt -alias wss40 -keystore wss40.jks
 * 
 */
public class SignatureCertTest extends org.junit.Assert {
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(SignatureCertTest.class);
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private Crypto crypto = null;
    private Crypto cryptoCA = null;
    
    public SignatureCertTest() throws Exception {
        WSSConfig.init();
        crypto = CryptoFactory.getInstance("wss40.properties");
        cryptoCA = CryptoFactory.getInstance("wss40CA.properties");
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
        Document signedDoc = sign.build(doc, crypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        //
        // Verify the signature
        //
        List<WSSecurityEngineResult> results = verify(signedDoc, cryptoCA);
        WSSecurityEngineResult result = 
            WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN);
        X509Certificate cert = 
            (X509Certificate)result.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE);
        assertTrue (cert != null);
    }
    
    // TODO disabling this test as the certs are expired
    @org.junit.Test
    @org.junit.Ignore
    public void testBSTCertChain() throws Exception {
        //
        // This test fails with the IBM JDK
        //
        if ("IBM Corporation".equals(System.getProperty("java.vendor"))) {
            return;
        }
        Crypto clientCrypto = CryptoFactory.getInstance("wss40_client.properties");
        WSSecSignature sign = new WSSecSignature();
        sign.setUserInfo("Client_CertChain", "password");
        sign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        sign.setUseSingleCertificate(false);
       
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = sign.build(doc, clientCrypto, secHeader);
                
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug("BST CA Cert");
            LOG.debug(outputString);
        }
        //
        // Verify the signature
        //
        Crypto serverCrypto = CryptoFactory.getInstance("wss40_server.properties");
        List<WSSecurityEngineResult> results = verify(signedDoc, serverCrypto);
        WSSecurityEngineResult result = 
            WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN);
        X509Certificate cert = 
            (X509Certificate)result.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE);
        assertTrue (cert != null);
        X509Certificate[] certs = 
            (X509Certificate[])result.get(WSSecurityEngineResult.TAG_X509_CERTIFICATES);
        assertTrue (certs != null && certs.length == 2);
    }
    
    /**
     * Test signing a SOAP message using a BST, sending the CA cert as well in the
     * message.
     */
    @org.junit.Test
    public void testSignatureDirectReferenceCACert() throws Exception {
        WSSecSignature sign = new WSSecSignature();
        sign.setUserInfo("wss40", "security");
        sign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        sign.setUseSingleCertificate(false);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = sign.build(doc, crypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug("BST CA Cert");
            LOG.debug(outputString);
        }
        //
        // Verify the signature
        //
        List<WSSecurityEngineResult> results = verify(signedDoc, cryptoCA);
        WSSecurityEngineResult result = 
            WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN);
        X509Certificate cert = 
            (X509Certificate)result.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE);
        assertTrue (cert != null);
        X509Certificate[] certs = 
            (X509Certificate[])result.get(WSSecurityEngineResult.TAG_X509_CERTIFICATES);
        assertTrue (certs != null && certs.length == 2);
    }
    
    
    /**
     * Test signing a SOAP message using Issuer Serial. Note that this should fail, as the
     * trust-store does not contain the cert corresponding to wss40, only the CA cert
     * wss40CA.
     */
    @org.junit.Test
    public void testSignatureIssuerSerial() throws Exception {
        WSSecSignature sign = new WSSecSignature();
        sign.setUserInfo("wss40", "security");
        sign.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = sign.build(doc, crypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        try {
            verify(signedDoc, cryptoCA);
            fail("Failure expected on issuer serial");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.FAILED_CHECK);
            // expected
        }
    }
    
    
    /**
     * Test signing a SOAP message using a BST. The signature verification passes, but the trust
     * verification will fail as the CA cert is out of date.
     */
    @org.junit.Test
    public void testSignatureBadCACert() throws Exception {
        WSSecSignature sign = new WSSecSignature();
        sign.setUserInfo("wss4jcertdsa", "security");
        sign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = 
            sign.build(doc, CryptoFactory.getInstance("wss40badca.properties"), secHeader);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        //
        // Verify the signature
        //
        try {
            verify(signedDoc, CryptoFactory.getInstance("wss40badcatrust.properties"));
            fail("Failure expected on bad CA cert!");
        } catch (WSSecurityException ex) {
            // expected
        }
    }
    
    /**
     * A test for "SignatureAction does not set DigestAlgorithm on WSSecSignature instance"
     */
    @org.junit.Test
    public void testMultipleCertsWSHandler() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final int action = WSConstants.SIGN;
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        reqData.setUsername("wss40");
        java.util.Map<String, String> config = new java.util.TreeMap<String, String>();
        config.put(WSHandlerConstants.SIG_PROP_FILE, "wss40.properties");
        config.put("password", "security");
        config.put(WSHandlerConstants.SIG_KEY_ID, "DirectReference");
        config.put(WSHandlerConstants.USE_SINGLE_CERTIFICATE, "false");
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
        
        //
        // Verify the signature
        //
        List<WSSecurityEngineResult> results = verify(doc, cryptoCA);
        WSSecurityEngineResult result = 
            WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN);
        X509Certificate cert = 
            (X509Certificate)result.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE);
        assertTrue (cert != null);
        X509Certificate[] certs = 
            (X509Certificate[])result.get(WSSecurityEngineResult.TAG_X509_CERTIFICATES);
        assertTrue (certs != null && certs.length == 2);
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
            doc, null, null, crypto
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
