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
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * This is a test for Certificate Revocation List checking. A message is signed and sent to the
 * receiver. If Certificate Revocation is enabled, then signature trust verification should
 * fail as the message has been signed by the private key corresponding to a revoked signature. 
 * 
 * Generate the client keypair, make a csr, sign it with the CA key
 * 
 * keytool -genkey -validity 3650 -alias wss40rev -keyalg RSA -keystore wss40rev.jks 
 * -dname "CN=Colm,OU=WSS4J,O=Apache,L=Dublin,ST=Leinster,C=IE"
 * keytool -certreq -alias wss40rev -keystore wss40rev.jks -file wss40rev.cer
 * openssl ca -config ca.config -policy policy_anything -days 3650 -out wss40rev.pem 
 * -infiles wss40rev.cer
 * openssl x509 -outform DER -in wss40rev.pem -out wss40rev.crt
 * 
 * Import the CA cert into wss40.jks and import the new signed certificate
 * 
 * keytool -import -file wss40CA.crt -alias wss40CA -keystore wss40rev.jks
 * keytool -import -file wss40rev.crt -alias wss40rev -keystore wss40rev.jks
 * 
 * Generate a Revocation list
 * 
 * openssl ca -gencrl -keyfile wss40CAKey.pem -cert wss40CA.pem -out wss40CACRL.pem 
 * -config ca.config -crldays 3650
 * openssl ca -revoke wss40rev.pem -keyfile wss40CAKey.pem -cert wss40CA.pem -config ca.config
 * openssl ca -gencrl -keyfile wss40CAKey.pem -cert wss40CA.pem -out wss40CACRL.pem 
 * -config ca.config -crldays 3650
 */
public class SignatureCRLTest extends org.junit.Assert {
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(SignatureCRLTest.class);
    private Crypto crypto = null;
    private Crypto cryptoCA = null;
    
    public SignatureCRLTest() throws Exception {
        WSSConfig.init();
        crypto = CryptoFactory.getInstance("wss40rev.properties");
        cryptoCA = CryptoFactory.getInstance("wss40CA.properties");
    }

    /**
     * Test signing a SOAP message using a BST. Revocation is not enabled and so the test
     * should pass.
     */
    @org.junit.Test
    public void testSignatureDirectReference() throws Exception {
        WSSecSignature sign = new WSSecSignature();
        sign.setUserInfo("wss40rev", "security");
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
        List<WSSecurityEngineResult> results = verify(signedDoc, cryptoCA, false);
        WSSecurityEngineResult result = 
            WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN);
        X509Certificate cert = 
            (X509Certificate)result.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE);
        assertTrue (cert != null);
    }
    
    /**
     * Test signing a SOAP message using a BST. Revocation is enabled and so the test
     * should fail.
     */
    @org.junit.Test
    public void testSignatureDirectReferenceRevocation() throws Exception {
        WSSecSignature sign = new WSSecSignature();
        sign.setUserInfo("wss40rev", "security");
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
        try {
            verify(signedDoc, cryptoCA, true);
            fail ("Failure expected on a revoked certificate");
        } catch (Exception ex) {
            String errorMessage = ex.getMessage();
            // Different errors using different JDKs...
            assertTrue(errorMessage.contains("Certificate has been revoked")
                || errorMessage.contains("Certificate revocation")
                || errorMessage.contains("Error during certificate path validation"));
        }
    }
    
    
    /**
     * Test signing a SOAP message using a BST. Revocation is enabled and so the test
     * should fail. The trust store that is used is the keystore that contains the revoked
     * certificate. See WSS-341:
     * https://issues.apache.org/jira/browse/WSS-341
     */
    @org.junit.Test
    public void testSignatureDirectReferenceRevocationKeyStore() throws Exception {
        WSSecSignature sign = new WSSecSignature();
        sign.setUserInfo("wss40rev", "security");
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
        try {
            verify(signedDoc, crypto, true);
            fail ("Failure expected on a revoked certificate");
        } catch (Exception ex) {
            String errorMessage = ex.getMessage();
            // Different errors using different JDKs...
            assertTrue(errorMessage.contains("Certificate has been revoked")
                || errorMessage.contains("Certificate revocation")
                || errorMessage.contains("Error during certificate path validation"));
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
    verify(Document doc, Crypto crypto, boolean revocationEnabled) throws WSSecurityException {
        WSSecurityEngine secEngine = new WSSecurityEngine();
        RequestData reqData = new RequestData();
        reqData.setSigCrypto(crypto);
        reqData.setEnableRevocation(revocationEnabled);
        Element securityHeader = WSSecurityUtil.getSecurityHeader(doc, null);
        List<WSSecurityEngineResult> results = 
            secEngine.processSecurityHeader(securityHeader, reqData);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Verfied and decrypted message:");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        return results;
    }

    
}
