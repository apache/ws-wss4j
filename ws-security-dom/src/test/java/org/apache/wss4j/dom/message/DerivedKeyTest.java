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
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.message.token.SecurityTokenReference;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.w3c.dom.Document;

import java.security.cert.X509Certificate;
import java.util.List;

import javax.security.auth.callback.CallbackHandler;

/**
 * A set of tests for using a derived key for encryption/signature.
 */
public class DerivedKeyTest extends org.junit.Assert {
    private static final org.slf4j.Logger LOG = 
        org.slf4j.LoggerFactory.getLogger(DerivedKeyTest.class);
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private CallbackHandler callbackHandler = new KeystoreCallbackHandler();
    private Crypto crypto = null;
    
    @org.junit.AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }
    
    public DerivedKeyTest() throws Exception {
        crypto = CryptoFactory.getInstance("wss40.properties");
        WSSConfig.init();
    }

    /**
     * Test encryption using a DerivedKeyToken using TRIPLEDES
     * @throws Exception Thrown when there is any problem in signing or 
     * verification
     */
    @org.junit.Test
    public void testEncryptionDecryptionTRIPLEDES() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        //EncryptedKey
        WSSecEncryptedKey encrKeyBuilder = new WSSecEncryptedKey();
        encrKeyBuilder.setUserInfo("wss40");
        encrKeyBuilder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
        encrKeyBuilder.prepare(doc, crypto);

        //Key information from the EncryptedKey
        byte[] ek = encrKeyBuilder.getEphemeralKey();
        String tokenIdentifier = encrKeyBuilder.getId();  
        
        //Derived key encryption
        WSSecDKEncrypt encrBuilder = new WSSecDKEncrypt();
        encrBuilder.setSymmetricEncAlgorithm(WSConstants.AES_128);
        encrBuilder.setExternalKey(ek, tokenIdentifier);
        Document encryptedDoc = encrBuilder.build(doc, secHeader);
        
        encrKeyBuilder.prependToHeader(secHeader);
        encrKeyBuilder.prependBSTElementToHeader(secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Encrypted message: 3DES  + DerivedKeys");
            String outputString = 
                XMLUtils.PrettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }
        verify(doc);
    }

    /**
     * Test encryption using a DerivedKeyToken using AES128 
     * @throws Exception Thrown when there is any problem in signing or verification
     */
    @org.junit.Test
    public void testEncryptionDecryptionAES128() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        //EncryptedKey
        WSSecEncryptedKey encrKeyBuilder = new WSSecEncryptedKey();
        encrKeyBuilder.setUserInfo("wss40");
        encrKeyBuilder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
        encrKeyBuilder.prepare(doc, crypto);

        //Key information from the EncryptedKey
        byte[] ek = encrKeyBuilder.getEphemeralKey();
        String tokenIdentifier = encrKeyBuilder.getId();  

        //Derived key encryption
        WSSecDKEncrypt encrBuilder = new WSSecDKEncrypt();
        encrBuilder.setSymmetricEncAlgorithm(WSConstants.AES_128);
        encrBuilder.setExternalKey(ek, tokenIdentifier);
        Document encryptedDoc = encrBuilder.build(doc, secHeader);

        encrKeyBuilder.prependToHeader(secHeader);
        encrKeyBuilder.prependBSTElementToHeader(secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Encrypted message: 3DES  + DerivedKeys");
            String outputString = 
                XMLUtils.PrettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }
        verify(doc);
     }
     
    @org.junit.Test
    public void testSignature() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        //EncryptedKey
        WSSecEncryptedKey encrKeyBuilder = new WSSecEncryptedKey();
        encrKeyBuilder.setUserInfo("wss40");
        encrKeyBuilder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
        encrKeyBuilder.prepare(doc, crypto);

        //Key information from the EncryptedKey
        byte[] ek = encrKeyBuilder.getEphemeralKey();
        String tokenIdentifier = encrKeyBuilder.getId();         

        //Derived key encryption
        WSSecDKSign sigBuilder = new WSSecDKSign();
        sigBuilder.setExternalKey(ek, tokenIdentifier);
        sigBuilder.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
        /* Document signedDoc = */ sigBuilder.build(doc, secHeader);

        encrKeyBuilder.prependToHeader(secHeader);
        encrKeyBuilder.prependBSTElementToHeader(secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed message: 3DES  + DerivedKeys");
            String outputString = 
                XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        List<WSSecurityEngineResult> results = verify(doc);
        
        WSSecurityEngineResult actionResult = 
            WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN);
        assertTrue(actionResult != null);
        assertFalse(actionResult.isEmpty());
        assertTrue(actionResult.get(WSSecurityEngineResult.TAG_SECRET) != null);
    }


    /**
     * A test for WSS-211 - "WSS4J does not support ThumbprintSHA1 in DerivedKeyTokens".
     * Here we're signing the SOAP body, where the signature refers to a DerivedKeyToken
     * which uses a Thumbprint-SHA1 reference to the encoded certificate (which is in the
     * keystore)
     */
    @org.junit.Test
    public void testSignatureThumbprintSHA1() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        SecurityTokenReference secToken = new SecurityTokenReference(doc);
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("wss40");
        X509Certificate[] certs = crypto.getX509Certificates(cryptoType);
        secToken.setKeyIdentifierThumb(certs[0]);

        WSSecDKSign sigBuilder = new WSSecDKSign();
        java.security.Key key = crypto.getPrivateKey("wss40", "security");
        sigBuilder.setExternalKey(key.getEncoded(), secToken.getElement());
        sigBuilder.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
        sigBuilder.build(doc, secHeader);

        sigBuilder.prependDKElementToHeader(secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Encrypted message: ThumbprintSHA1 + DerivedKeys");
            String outputString = 
                XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        List<WSSecurityEngineResult> results = verify(doc);
        
        WSSecurityEngineResult actionResult = 
            WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN);
        assertTrue(actionResult != null);
        assertFalse(actionResult.isEmpty());
        assertTrue(actionResult.get(WSSecurityEngineResult.TAG_SECRET) != null);
    }


    /**
     * Here we're signing the SOAP body, where the signature refers to a DerivedKeyToken
     * which uses an SKI reference to the encoded certificate (which is in the
     * keystore)
     */
    @org.junit.Test
    public void testSignatureSKI() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        SecurityTokenReference secToken = new SecurityTokenReference(doc);
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("wss40");
        X509Certificate[] certs = crypto.getX509Certificates(cryptoType);
        secToken.setKeyIdentifierSKI(certs[0], crypto);

        WSSecDKSign sigBuilder = new WSSecDKSign();
        java.security.Key key = crypto.getPrivateKey("wss40", "security");
        sigBuilder.setExternalKey(key.getEncoded(), secToken.getElement());
        sigBuilder.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
        sigBuilder.build(doc, secHeader);

        sigBuilder.prependDKElementToHeader(secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Encrypted message: SKI + DerivedKeys");
            String outputString = 
                XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        List<WSSecurityEngineResult> results = verify(doc);
        
        WSSecurityEngineResult actionResult = 
            WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN);
        assertTrue(actionResult != null);
        assertFalse(actionResult.isEmpty());
        assertTrue(actionResult.get(WSSecurityEngineResult.TAG_SECRET) != null);
    }

    @org.junit.Test
    public void testSignatureEncrypt() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        //EncryptedKey
        WSSecEncryptedKey encrKeyBuilder = new WSSecEncryptedKey();
        encrKeyBuilder.setUserInfo("wss40");
        encrKeyBuilder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
        encrKeyBuilder.prepare(doc, crypto);

        //Key information from the EncryptedKey
        byte[] ek = encrKeyBuilder.getEphemeralKey();
        String tokenIdentifier = encrKeyBuilder.getId();

        //Derived key encryption
        WSSecDKSign sigBuilder = new WSSecDKSign();
        sigBuilder.setExternalKey(ek, tokenIdentifier);
        sigBuilder.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
        LOG.info("Before HMAC-SHA1 signature");
        Document signedDoc = sigBuilder.build(doc, secHeader);

        //Derived key signature
        WSSecDKEncrypt encrBuilder = new WSSecDKEncrypt();
        encrBuilder.setSymmetricEncAlgorithm(WSConstants.AES_128);
        encrBuilder.setExternalKey(ek, tokenIdentifier);
        Document signedEncryptedDoc = encrBuilder.build(signedDoc, secHeader);

        encrKeyBuilder.prependToHeader(secHeader);
        encrKeyBuilder.prependBSTElementToHeader(secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Encrypted message: 3DES  + DerivedKeys");
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedEncryptedDoc);
            LOG.debug(outputString);
        }
        verify(signedEncryptedDoc);
    }

    @org.junit.Test
    public void testEncryptSignature() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        //EncryptedKey
        WSSecEncryptedKey encrKeyBuilder = new WSSecEncryptedKey();
        encrKeyBuilder.setUserInfo("wss40");
        encrKeyBuilder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
        encrKeyBuilder.prepare(doc, crypto);

        //Key information from the EncryptedKey
        byte[] ek = encrKeyBuilder.getEphemeralKey();
        String tokenIdentifier = encrKeyBuilder.getId();

        //Derived key encryption
        WSSecDKEncrypt encrBuilder = new WSSecDKEncrypt();
        encrBuilder.setSymmetricEncAlgorithm(WSConstants.AES_128);
        encrBuilder.setExternalKey(ek, tokenIdentifier);
        encrBuilder.build(doc, secHeader);

        //Derived key signature
        WSSecDKSign sigBuilder = new WSSecDKSign();
        sigBuilder.setExternalKey(ek, tokenIdentifier);
        sigBuilder.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
        LOG.info("Before HMAC-SHA1 signature");
        Document encryptedSignedDoc = sigBuilder.build(doc, secHeader);

        encrKeyBuilder.prependToHeader(secHeader);
        encrKeyBuilder.prependBSTElementToHeader(secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Encrypted message: 3DES  + DerivedKeys");
            String outputString = 
                XMLUtils.PrettyDocumentToString(encryptedSignedDoc);
            LOG.debug(outputString);
        }

        verify(encryptedSignedDoc);
    }

    /**
     * Verifies the soap envelope
     * <p/>
     * 
     * @param envelope 
     * @throws Exception Thrown when there is a problem in verification
     */
    private List<WSSecurityEngineResult> verify(Document doc) throws Exception {
        List<WSSecurityEngineResult> results = 
            secEngine.processSecurityHeader(doc, null, callbackHandler, crypto);
        String outputString = 
            XMLUtils.PrettyDocumentToString(doc);
        assertTrue(outputString.indexOf("counter_port_type") > 0 ? true : false);
        
        return results;
    }

}
