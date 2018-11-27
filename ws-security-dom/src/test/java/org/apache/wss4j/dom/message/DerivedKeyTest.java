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
import org.apache.wss4j.dom.common.KeystoreCallbackHandler;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.junit.Test;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.token.SecurityTokenReference;
import org.apache.wss4j.common.util.XMLUtils;
import org.w3c.dom.Document;

import java.security.cert.X509Certificate;

import javax.security.auth.callback.CallbackHandler;

/**
 * A set of tests for using a derived key for encryption/signature.
 */
public class DerivedKeyTest extends org.junit.Assert {
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(DerivedKeyTest.class);
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private CallbackHandler callbackHandler = new KeystoreCallbackHandler();
    private Crypto crypto;

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
    @Test
    public void testEncryptionDecryptionTRIPLEDES() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        //EncryptedKey
        WSSecEncryptedKey encrKeyBuilder = new WSSecEncryptedKey(secHeader);
        encrKeyBuilder.setUserInfo("wss40");
        encrKeyBuilder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
        encrKeyBuilder.prepare(crypto);

        //Key information from the EncryptedKey
        byte[] ek = encrKeyBuilder.getEphemeralKey();
        String tokenIdentifier = encrKeyBuilder.getId();

        //Derived key encryption
        WSSecDKEncrypt encrBuilder = new WSSecDKEncrypt(secHeader);
        encrBuilder.setSymmetricEncAlgorithm(WSConstants.AES_128);
        encrBuilder.setExternalKey(ek, tokenIdentifier);
        Document encryptedDoc = encrBuilder.build();

        encrKeyBuilder.prependToHeader();
        encrKeyBuilder.prependBSTElementToHeader();

        if (LOG.isDebugEnabled()) {
            LOG.debug("Encrypted message: 3DES  + DerivedKeys");
            String outputString =
                XMLUtils.prettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }
        verify(doc);
    }

    /**
     * Test encryption using a DerivedKeyToken using AES128
     * @throws Exception Thrown when there is any problem in signing or verification
     */
    @Test
    public void testEncryptionDecryptionAES128() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        //EncryptedKey
        WSSecEncryptedKey encrKeyBuilder = new WSSecEncryptedKey(secHeader);
        encrKeyBuilder.setUserInfo("wss40");
        encrKeyBuilder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
        encrKeyBuilder.prepare(crypto);

        //Key information from the EncryptedKey
        byte[] ek = encrKeyBuilder.getEphemeralKey();
        String tokenIdentifier = encrKeyBuilder.getId();

        //Derived key encryption
        WSSecDKEncrypt encrBuilder = new WSSecDKEncrypt(secHeader);
        encrBuilder.setSymmetricEncAlgorithm(WSConstants.AES_128);
        encrBuilder.setExternalKey(ek, tokenIdentifier);
        Document encryptedDoc = encrBuilder.build();

        encrKeyBuilder.prependToHeader();
        encrKeyBuilder.prependBSTElementToHeader();

        if (LOG.isDebugEnabled()) {
            LOG.debug("Encrypted message: 3DES  + DerivedKeys");
            String outputString =
                XMLUtils.prettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }
        verify(doc);
     }

    @Test
    public void testSignature() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        //EncryptedKey
        WSSecEncryptedKey encrKeyBuilder = new WSSecEncryptedKey(secHeader);
        encrKeyBuilder.setUserInfo("wss40");
        encrKeyBuilder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
        encrKeyBuilder.prepare(crypto);

        //Key information from the EncryptedKey
        byte[] ek = encrKeyBuilder.getEphemeralKey();
        String tokenIdentifier = encrKeyBuilder.getId();

        //Derived key encryption
        WSSecDKSign sigBuilder = new WSSecDKSign(secHeader);
        sigBuilder.setExternalKey(ek, tokenIdentifier);
        sigBuilder.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
        /* Document signedDoc = */ sigBuilder.build();

        encrKeyBuilder.prependToHeader();
        encrKeyBuilder.prependBSTElementToHeader();

        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed message: 3DES  + DerivedKeys");
            String outputString =
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        WSHandlerResult results = verify(doc);

        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.SIGN).get(0);
        assertNotNull(actionResult);
        assertFalse(actionResult.isEmpty());
        assertNotNull(actionResult.get(WSSecurityEngineResult.TAG_SECRET));
    }


    /**
     * A test for WSS-211 - "WSS4J does not support ThumbprintSHA1 in DerivedKeyTokens".
     * Here we're signing the SOAP body, where the signature refers to a DerivedKeyToken
     * which uses a Thumbprint-SHA1 reference to the encoded certificate (which is in the
     * keystore)
     */
    @Test
    public void testSignatureThumbprintSHA1() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        SecurityTokenReference secToken = new SecurityTokenReference(doc);
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("wss40");
        X509Certificate[] certs = crypto.getX509Certificates(cryptoType);
        secToken.setKeyIdentifierThumb(certs[0]);

        WSSecDKSign sigBuilder = new WSSecDKSign(secHeader);
        java.security.Key key = crypto.getPrivateKey("wss40", "security");
        sigBuilder.setExternalKey(key.getEncoded(), secToken.getElement());
        sigBuilder.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
        sigBuilder.build();

        sigBuilder.prependDKElementToHeader();

        if (LOG.isDebugEnabled()) {
            LOG.debug("Encrypted message: ThumbprintSHA1 + DerivedKeys");
            String outputString =
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        WSHandlerResult results = verify(doc);

        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.SIGN).get(0);
        assertNotNull(actionResult);
        assertFalse(actionResult.isEmpty());
        assertNotNull(actionResult.get(WSSecurityEngineResult.TAG_SECRET));
    }


    /**
     * Here we're signing the SOAP body, where the signature refers to a DerivedKeyToken
     * which uses an SKI reference to the encoded certificate (which is in the
     * keystore)
     */
    @Test
    public void testSignatureSKI() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        SecurityTokenReference secToken = new SecurityTokenReference(doc);
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("wss40");
        X509Certificate[] certs = crypto.getX509Certificates(cryptoType);
        secToken.setKeyIdentifierSKI(certs[0], crypto);

        WSSecDKSign sigBuilder = new WSSecDKSign(secHeader);
        java.security.Key key = crypto.getPrivateKey("wss40", "security");
        sigBuilder.setExternalKey(key.getEncoded(), secToken.getElement());
        sigBuilder.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
        sigBuilder.build();

        sigBuilder.prependDKElementToHeader();

        if (LOG.isDebugEnabled()) {
            LOG.debug("Encrypted message: SKI + DerivedKeys");
            String outputString =
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        WSHandlerResult results = verify(doc);

        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.SIGN).get(0);
        assertNotNull(actionResult);
        assertFalse(actionResult.isEmpty());
        assertNotNull(actionResult.get(WSSecurityEngineResult.TAG_SECRET));
    }

    @Test
    public void testSignatureEncrypt() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        //EncryptedKey
        WSSecEncryptedKey encrKeyBuilder = new WSSecEncryptedKey(secHeader);
        encrKeyBuilder.setUserInfo("wss40");
        encrKeyBuilder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
        encrKeyBuilder.prepare(crypto);

        //Key information from the EncryptedKey
        byte[] ek = encrKeyBuilder.getEphemeralKey();
        String tokenIdentifier = encrKeyBuilder.getId();

        //Derived key encryption
        WSSecDKSign sigBuilder = new WSSecDKSign(secHeader);
        sigBuilder.setExternalKey(ek, tokenIdentifier);
        sigBuilder.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
        LOG.info("Before HMAC-SHA1 signature");
        sigBuilder.build();

        //Derived key signature
        WSSecDKEncrypt encrBuilder = new WSSecDKEncrypt(secHeader);
        encrBuilder.setSymmetricEncAlgorithm(WSConstants.AES_128);
        encrBuilder.setExternalKey(ek, tokenIdentifier);
        Document signedEncryptedDoc = encrBuilder.build();

        encrKeyBuilder.prependToHeader();
        encrKeyBuilder.prependBSTElementToHeader();

        if (LOG.isDebugEnabled()) {
            LOG.debug("Encrypted message: 3DES  + DerivedKeys");
            String outputString =
                XMLUtils.prettyDocumentToString(signedEncryptedDoc);
            LOG.debug(outputString);
        }
        verify(signedEncryptedDoc);
    }

    @Test
    public void testEncryptSignature() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        //EncryptedKey
        WSSecEncryptedKey encrKeyBuilder = new WSSecEncryptedKey(secHeader);
        encrKeyBuilder.setUserInfo("wss40");
        encrKeyBuilder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
        encrKeyBuilder.prepare(crypto);

        //Key information from the EncryptedKey
        byte[] ek = encrKeyBuilder.getEphemeralKey();
        String tokenIdentifier = encrKeyBuilder.getId();

        //Derived key encryption
        WSSecDKEncrypt encrBuilder = new WSSecDKEncrypt(secHeader);
        encrBuilder.setSymmetricEncAlgorithm(WSConstants.AES_128);
        encrBuilder.setExternalKey(ek, tokenIdentifier);
        encrBuilder.build();

        //Derived key signature
        WSSecDKSign sigBuilder = new WSSecDKSign(secHeader);
        sigBuilder.setExternalKey(ek, tokenIdentifier);
        sigBuilder.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
        LOG.info("Before HMAC-SHA1 signature");
        Document encryptedSignedDoc = sigBuilder.build();

        encrKeyBuilder.prependToHeader();
        encrKeyBuilder.prependBSTElementToHeader();

        if (LOG.isDebugEnabled()) {
            LOG.debug("Encrypted message: 3DES  + DerivedKeys");
            String outputString =
                XMLUtils.prettyDocumentToString(encryptedSignedDoc);
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
    private WSHandlerResult verify(Document doc) throws Exception {
        WSHandlerResult results =
            secEngine.processSecurityHeader(doc, null, callbackHandler, crypto);
        String outputString =
            XMLUtils.prettyDocumentToString(doc);
        assertTrue(outputString.indexOf("counter_port_type") > 0 ? true : false);

        return results;
    }

}
