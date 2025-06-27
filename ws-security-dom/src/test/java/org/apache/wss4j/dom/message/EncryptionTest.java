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

import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.UUID;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.callback.CallbackHandler;

import org.apache.wss4j.common.SOAPConstants;
import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.WSS4JConstants;
import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.*;
import org.apache.wss4j.common.dom.WSConstants;
import org.apache.wss4j.common.WSDataRef;
import org.apache.wss4j.dom.common.CustomHandler;
import org.apache.wss4j.common.crypto.KeystoreCallbackHandler;
import org.apache.wss4j.dom.common.SecretKeyCallbackHandler;

import org.apache.wss4j.common.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.common.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.common.dom.message.WSSecHeader;
import org.apache.wss4j.dom.handler.HandlerAction;
import org.apache.wss4j.common.dom.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.dom.str.STRParser.REFERENCE_TYPE;
import org.apache.xml.security.encryption.params.HKDFParams;
import org.apache.xml.security.utils.EncryptionConstants;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * A set of test-cases for encrypting and decrypting SOAP requests.
 */
public class EncryptionTest {
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(EncryptionTest.class);
    private static final javax.xml.namespace.QName SOAP_BODY =
        new javax.xml.namespace.QName(
            WSConstants.URI_SOAP11_ENV,
            "Body"
        );

    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private CallbackHandler keystoreCallbackHandler = new KeystoreCallbackHandler();
    private SecretKeyCallbackHandler secretKeyCallbackHandler = new SecretKeyCallbackHandler();
    private byte[] keyData;
    private SecretKey key;
    private Crypto crypto;

    public EncryptionTest() throws Exception {
        crypto = CryptoFactory.getInstance("wss40.properties");
    }

    /**
     * Setup method
     *
     * @throws Exception Thrown when there is a problem in setup
     */
    @BeforeEach
    public void setUp() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        key = keyGen.generateKey();
        keyData = key.getEncoded();
        secEngine.setWssConfig(WSSConfig.getNewInstance());
    }

    @AfterEach
    public void cleanup() {
        JDKTestUtils.unregisterAuxiliaryProvider();
    }

    /**
     * Test that encrypt and decrypt a WS-Security envelope.
     * This test uses the RSA_15 algorithm to transport (wrap) the symmetric
     * key.
     * <p/>
     *
     * @throws Exception Thrown when there is any problem in signing or verification
     */
    @Test
    public void testEncryptionDecryptionRSA15() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecEncrypt builder = new WSSecEncrypt(secHeader);
        builder.setUserInfo("wss40");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        builder.setSymmetricEncAlgorithm(WSConstants.TRIPLE_DES);

        LOG.info("Before Encryption Triple DES....");
        KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.TRIPLE_DES);
        SecretKey symmetricKey = keyGen.generateKey();
        Document encryptedDoc = builder.build(crypto, symmetricKey);
        LOG.info("After Encryption Triple DES....");

        String outputString =
            XMLUtils.prettyDocumentToString(encryptedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Encrypted message, RSA-15 keytransport, 3DES:");
            LOG.debug(outputString);
        }
        assertFalse(outputString.contains("counter_port_type"));
        verify(encryptedDoc, keystoreCallbackHandler, SOAP_BODY);
        builder.getParts().clear();

        /*
         * second run, same Junit set up, but change encryption method,
         * key identification, encryption mode (Element now), and data to encrypt.
         * This tests if several runs of different algorithms on same builder/cipher
         * setup are ok.
         */
        doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        builder = new WSSecEncrypt(secHeader);
        builder.setUserInfo("wss40");
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        builder.setSymmetricEncAlgorithm(WSConstants.AES_128);

        WSEncryptionPart encP =
            new WSEncryptionPart(
                "add", "http://ws.apache.org/counter/counter_port_type", "Element"
            );
        builder.getParts().add(encP);

        LOG.info("Before Encryption AES 128/RSA-15....");
        keyGen = KeyUtils.getKeyGenerator(WSConstants.AES_128);
        symmetricKey = keyGen.generateKey();
        encryptedDoc = builder.build(crypto, symmetricKey);
        LOG.info("After Encryption AES 128/RSA-15....");
        outputString =
            XMLUtils.prettyDocumentToString(encryptedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Encrypted message, RSA-15 keytransport, AES 128:");
            LOG.debug(outputString);
        }
        assertFalse(outputString.contains("counter_port_type"));
        WSHandlerResult results = verify(
            encryptedDoc,
            keystoreCallbackHandler,
            new javax.xml.namespace.QName(
                "http://ws.apache.org/counter/counter_port_type",
                "add"
            )
        );

        WSSecurityEngineResult actionResult =
                results.getActionResults().get(WSConstants.ENCR).get(0);
        assertNotNull(actionResult.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE));
        assertNotNull(actionResult.get(WSSecurityEngineResult.TAG_X509_REFERENCE_TYPE));
        REFERENCE_TYPE referenceType =
            (REFERENCE_TYPE)actionResult.get(WSSecurityEngineResult.TAG_X509_REFERENCE_TYPE);
        assertTrue(referenceType == REFERENCE_TYPE.ISSUER_SERIAL);
    }

    /**
     * Test that encrypt and decrypt a WS-Security envelope.
     * This test uses the RSA OAEP algorithm to transport (wrap) the symmetric
     * key.
     * <p/>
     *
     * @throws Exception Thrown when there is any problem in signing or verification
     */
    @Test
    public void testEncryptionDecryptionOAEP() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecEncrypt builder = new WSSecEncrypt(secHeader);
        builder.setUserInfo("wss40");
        builder.setKeyIdentifierType(WSConstants.X509_KEY_IDENTIFIER);
        builder.setKeyEncAlgo(WSConstants.KEYTRANSPORT_RSAOAEP);

        LOG.info("Before Encryption Triple DES/RSA-OAEP....");
        KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.AES_128);
        SecretKey symmetricKey = keyGen.generateKey();
        Document encryptedDoc = builder.build(crypto, symmetricKey);
        LOG.info("After Encryption Triple DES/RSA-OAEP....");

        String outputString =
            XMLUtils.prettyDocumentToString(encryptedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Encrypted message, RSA-OAEP keytransport, 3DES:");
            LOG.debug(outputString);
        }
        assertFalse(outputString.contains("counter_port_type"));

        WSSecurityEngine newEngine = new WSSecurityEngine();
        WSHandlerResult results =
            newEngine.processSecurityHeader(encryptedDoc, null, keystoreCallbackHandler, crypto);

        WSSecurityEngineResult actionResult =
                results.getActionResults().get(WSConstants.ENCR).get(0);
        assertNotNull(actionResult.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE));
        assertNotNull(actionResult.get(WSSecurityEngineResult.TAG_X509_REFERENCE_TYPE));
        REFERENCE_TYPE referenceType =
            (REFERENCE_TYPE)actionResult.get(WSSecurityEngineResult.TAG_X509_REFERENCE_TYPE);
        assertTrue(referenceType == REFERENCE_TYPE.KEY_IDENTIFIER);
    }

    @Test
    public void testEncryptionDecryptionPublicKey() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecEncrypt builder = new WSSecEncrypt(secHeader);
        builder.setKeyIdentifierType(WSConstants.KEY_VALUE);
        builder.setKeyEncAlgo(WSConstants.KEYTRANSPORT_RSAOAEP);

        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("wss40");
        X509Certificate[] certs = crypto.getX509Certificates(cryptoType);
        assertNotNull(certs);
        builder.setUseThisPublicKey(certs[0].getPublicKey());

        KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.AES_128);
        SecretKey symmetricKey = keyGen.generateKey();
        Document encryptedDoc = builder.build(crypto, symmetricKey);

        String outputString =
            XMLUtils.prettyDocumentToString(encryptedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        assertFalse(outputString.contains("counter_port_type"));

        WSSecurityEngine newEngine = new WSSecurityEngine();
        WSHandlerResult results =
            newEngine.processSecurityHeader(encryptedDoc, null, keystoreCallbackHandler, crypto);

        WSSecurityEngineResult actionResult =
                results.getActionResults().get(WSConstants.ENCR).get(0);
        assertNotNull(actionResult.get(WSSecurityEngineResult.TAG_PUBLIC_KEY));
    }

    /**
     * Test that encrypt and then again encrypts (Super encryption) WS-Security
     * envelope and then verifies it <p/>
     *
     * @throws Exception
     *             Thrown when there is any problem in encryption or
     *             verification
     */
    @Test
    public void testEncryptionEncryption() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        Crypto encCrypto = CryptoFactory.getInstance();
        WSSecEncrypt encrypt = new WSSecEncrypt(secHeader);
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e");
        LOG.info("Before Encryption....");

        KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.AES_128);
        SecretKey symmetricKey = keyGen.generateKey();
        Document encryptedDoc = encrypt.build(encCrypto, symmetricKey);

        if (LOG.isDebugEnabled()) {
            LOG.debug("After the first encryption:");
            String outputString =
                XMLUtils.prettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }

        Document encryptedEncryptedDoc = encrypt.build(encCrypto, symmetricKey);

        if (LOG.isDebugEnabled()) {
            LOG.debug("After the second encryption:");
            String outputString =
                XMLUtils.prettyDocumentToString(encryptedEncryptedDoc);
            LOG.debug(outputString);
        }

        LOG.info("After Encryption....");
        verify(encryptedEncryptedDoc, encCrypto, keystoreCallbackHandler);
    }

    /**
     * Test that encrypt and decrypt a WS-Security envelope.
     * This test uses the key agreement algorithm to (wrap) the symmetric key with generating KDF with
     * default parameter
     * <p/>
     *
     * @param algorithm The key type algorithm
     * @param certAlias The certificate alias from the configuration defined in wss-ecdh.properties
     * @param keyAgreementMethod The key agreement method
     * @param kdfAlgorithm The key derivation method
     * @throws Exception Thrown when there is any problem in signing or verification
     */
    @ParameterizedTest
    @CsvSource({"xdh, X25519, http://www.w3.org/2021/04/xmldsig-more#x25519, http://www.w3.org/2009/xmlenc11#ConcatKDF",
            "xdh, X448, http://www.w3.org/2021/04/xmldsig-more#x448, http://www.w3.org/2009/xmlenc11#ConcatKDF",
            "ec, secp256r1, http://www.w3.org/2009/xmlenc11#ECDH-ES, http://www.w3.org/2009/xmlenc11#ConcatKDF",
            "ec, secp384r1, http://www.w3.org/2009/xmlenc11#ECDH-ES, http://www.w3.org/2009/xmlenc11#ConcatKDF",
            "ec, secp521r1, http://www.w3.org/2009/xmlenc11#ECDH-ES, http://www.w3.org/2009/xmlenc11#ConcatKDF",
            "xdh, X25519, http://www.w3.org/2021/04/xmldsig-more#x25519, http://www.w3.org/2021/04/xmldsig-more#hkdf",
            "xdh, X448, http://www.w3.org/2021/04/xmldsig-more#x448, http://www.w3.org/2021/04/xmldsig-more#hkdf",
            "ec, secp256r1, http://www.w3.org/2009/xmlenc11#ECDH-ES, http://www.w3.org/2021/04/xmldsig-more#hkdf",
            "ec, secp384r1, http://www.w3.org/2009/xmlenc11#ECDH-ES, http://www.w3.org/2021/04/xmldsig-more#hkdf",
            "ec, secp521r1, http://www.w3.org/2009/xmlenc11#ECDH-ES, http://www.w3.org/2021/04/xmldsig-more#hkdf",
    })
    public void testEncryptionDecryptionWithKeyAgreementAndDefaultKDF(String algorithm, String certAlias, String keyAgreementMethod, String kdfAlgorithm) throws Exception {
        try {
            if (!JDKTestUtils.isAlgorithmSupportedByJDK(algorithm)) {
                LOG.info("Add AuxiliaryProvider to execute test with algorithm [{}] and cert alias [{}]", algorithm, certAlias);
                Security.addProvider(JDKTestUtils.getAuxiliaryProvider());
            } else if (JDKTestUtils.getJDKVersion() == 11 && algorithm.equals("xdh")) {
                // workaround for jdk11 and xdh keys
                // https://bugs.openjdk.java.net/browse/JDK-8219381 or https://bugs.openjdk.org/browse/JDK-8213363
                // set the auxiliary provider as first provider to parse the xdh private key
                Security.insertProviderAt(JDKTestUtils.getAuxiliaryProvider(), 1);
            }
            Crypto encCrypto = CryptoFactory.getInstance("wss-ecdh.properties");

            Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
            WSSecHeader secHeader = new WSSecHeader(doc);
            secHeader.insertSecurityHeader();

            WSSecEncrypt builder = new WSSecEncrypt(secHeader);
            builder.setUserInfo(certAlias);
            builder.setKeyEncAlgo(WSConstants.KEYWRAP_AES128);
            builder.setKeyAgreementMethod(keyAgreementMethod);
            builder.setKeyDerivationMethod(kdfAlgorithm);
            if (kdfAlgorithm.equalsIgnoreCase(WSS4JConstants.KEYDERIVATION_CONCATKDF)){
                builder.setDigestAlgorithm(WSS4JConstants.SHA256);
            }
            builder.setKeyIdentifierType(WSConstants.SKI_KEY_IDENTIFIER);

            LOG.info("Before Encryption ...");
            KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.AES_128_GCM);
            SecretKey symmetricKey = keyGen.generateKey();

            Document encryptedDoc = builder.build(encCrypto, symmetricKey);
            LOG.info("After Encryption ....");

            String outputString =
                    XMLUtils.prettyDocumentToString(encryptedDoc);

            if (LOG.isDebugEnabled()) {
                LOG.debug("Encrypted message:");
                LOG.debug(outputString);
            }
            assertFalse(outputString.contains("counter_port_type"));
            // Check for algorithms and agreement method element
            assertTrue(outputString.contains(EncryptionConstants._TAG_AGREEMENTMETHOD));
            assertTrue(outputString.contains(WSConstants.KEYWRAP_AES128));
            assertTrue(outputString.contains(keyAgreementMethod));

            WSSecurityEngine newEngine = new WSSecurityEngine();
            WSHandlerResult results =
                    newEngine.processSecurityHeader(encryptedDoc, null, keystoreCallbackHandler, encCrypto);

            WSSecurityEngineResult actionResult =
                    results.getActionResults().get(WSConstants.ENCR).get(0);
            assertNotNull(actionResult);
        } finally {
            Security.removeProvider(JDKTestUtils.getAuxiliaryProvider().getName());
        }
    }

    /**
     * Test that encrypt and decrypt a WS-Security envelope.
     * This test uses the ECDSA-ES algorithm to (wrap) the symmetric key.
     * <p/>
     *
     * @throws Exception Thrown when there is any problem in signing or verification
     */
    @ParameterizedTest
    @CsvSource({
            "xdh, X25519, http://www.w3.org/2021/04/xmldsig-more#x25519, http://www.w3.org/2001/04/xmlenc#kw-aes128, 128",
            "xdh, X448, http://www.w3.org/2021/04/xmldsig-more#x448, http://www.w3.org/2001/04/xmlenc#kw-aes128, 128",
            "ec, secp256r1, http://www.w3.org/2009/xmlenc11#ECDH-ES, http://www.w3.org/2001/04/xmlenc#kw-aes128, 128",
            "ec, secp384r1, http://www.w3.org/2009/xmlenc11#ECDH-ES, http://www.w3.org/2001/04/xmlenc#kw-aes128, 128",
            "ec, secp521r1, http://www.w3.org/2009/xmlenc11#ECDH-ES, http://www.w3.org/2001/04/xmlenc#kw-aes128, 128",
            "xdh, X25519, http://www.w3.org/2021/04/xmldsig-more#x25519, http://www.w3.org/2001/04/xmlenc#kw-aes192, 192",
            "xdh, X448, http://www.w3.org/2021/04/xmldsig-more#x448, http://www.w3.org/2001/04/xmlenc#kw-aes192, 192",
            "ec, secp256r1, http://www.w3.org/2009/xmlenc11#ECDH-ES, http://www.w3.org/2001/04/xmlenc#kw-aes192, 192",
            "ec, secp384r1, http://www.w3.org/2009/xmlenc11#ECDH-ES, http://www.w3.org/2001/04/xmlenc#kw-aes192, 192",
            "ec, secp521r1, http://www.w3.org/2009/xmlenc11#ECDH-ES, http://www.w3.org/2001/04/xmlenc#kw-aes192, 192",
            "xdh, X25519, http://www.w3.org/2021/04/xmldsig-more#x25519, http://www.w3.org/2001/04/xmlenc#kw-aes256, 256",
            "xdh, X448, http://www.w3.org/2021/04/xmldsig-more#x448, http://www.w3.org/2001/04/xmlenc#kw-aes256, 256",
            "ec, secp256r1, http://www.w3.org/2009/xmlenc11#ECDH-ES, http://www.w3.org/2001/04/xmlenc#kw-aes256, 256",
            "ec, secp384r1, http://www.w3.org/2009/xmlenc11#ECDH-ES, http://www.w3.org/2001/04/xmlenc#kw-aes256, 256",
            "ec, secp521r1, http://www.w3.org/2009/xmlenc11#ECDH-ES, http://www.w3.org/2001/04/xmlenc#kw-aes256, 256",
    })
    public void testEncryptionDecryptionWithKeyAgreementAndHKDF(String algorithm, String certAlias, String keyAgreementMethod, String keyWrapAlg, int keySize ) throws Exception {
        String hkdfMacFunction = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256";
        try {
            if (!JDKTestUtils.isAlgorithmSupportedByJDK(algorithm)) {
                LOG.info("Add AuxiliaryProvider to execute test with algorithm [{}] and cert alias [{}]", algorithm, certAlias);
                Security.addProvider(JDKTestUtils.getAuxiliaryProvider());
            } else if (JDKTestUtils.getJDKVersion() == 11 && algorithm.equals("xdh")) {
                // workaround for jdk11 and xdh keys
                // https://bugs.openjdk.java.net/browse/JDK-8219381 or https://bugs.openjdk.org/browse/JDK-8213363
                // set the auxiliary provider as first provider to parse the xdh private key
                Security.insertProviderAt(JDKTestUtils.getAuxiliaryProvider(), 1);
            }
            Crypto encCrypto = CryptoFactory.getInstance("wss-ecdh.properties");

            Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
            WSSecHeader secHeader = new WSSecHeader(doc);
            secHeader.insertSecurityHeader();

            HKDFParams keyDerivationParameters = HKDFParams.createBuilder(keySize, hkdfMacFunction)
                    .info("test-key-info".getBytes())
                    .salt(UUID.randomUUID().toString().getBytes())
                    .build();

            WSSecEncrypt builder = new WSSecEncrypt(secHeader);
            builder.setUserInfo(certAlias);
            builder.setKeyEncAlgo(keyWrapAlg);
            builder.setKeyAgreementMethod(keyAgreementMethod);
            builder.setKeyDerivationParameters(keyDerivationParameters);


            LOG.info("Before Encryption ...");
            KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.AES_128_GCM);
            SecretKey symmetricKey = keyGen.generateKey();

            Document encryptedDoc = builder.build(encCrypto, symmetricKey);
            LOG.info("After Encryption ....");

            String outputString =
                    XMLUtils.prettyDocumentToString(encryptedDoc);

            if (LOG.isDebugEnabled()) {
                LOG.debug("Encrypted message:");
                LOG.debug(outputString);
            }
            assertFalse(outputString.contains("counter_port_type"));
            // Check for algorithms and agreement method element
            assertTrue(outputString.contains(EncryptionConstants._TAG_AGREEMENTMETHOD));
            assertTrue(outputString.contains(EncryptionConstants._TAG_HKDFPARAMS));
            assertTrue(outputString.contains(EncryptionConstants._TAG_INFO));
            assertTrue(outputString.contains(EncryptionConstants._TAG_KEYLENGTH+">"+(keySize/8)+"</"));
            assertTrue(outputString.contains(hkdfMacFunction));

            assertTrue(outputString.contains(keyWrapAlg));
            assertTrue(outputString.contains(keyAgreementMethod));

            WSSecurityEngine newEngine = new WSSecurityEngine();
            WSHandlerResult results =
                    newEngine.processSecurityHeader(encryptedDoc, null, keystoreCallbackHandler, encCrypto);

            WSSecurityEngineResult actionResult =
                    results.getActionResults().get(WSConstants.ENCR).get(0);
            assertNotNull(actionResult);
        } finally {
            Security.removeProvider(JDKTestUtils.getAuxiliaryProvider().getName());
        }
    }

    /**
     * Test that encrypts and decrypts a WS-Security envelope.
     * The test uses the ThumbprintSHA1 key identifier type.
     * <p/>
     *
     * @throws Exception Thrown when there is any problem in encryption or decryption
     */
    @Test
    public void testX509EncryptionThumb() throws Exception {
        Crypto encCrypto = CryptoFactory.getInstance();
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecEncrypt builder = new WSSecEncrypt(secHeader);
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);

        LOG.info("Before Encrypting ThumbprintSHA1....");
        KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.AES_128);
        SecretKey symmetricKey = keyGen.generateKey();
        Document encryptedDoc = builder.build(encCrypto, symmetricKey);

        String outputString =
            XMLUtils.prettyDocumentToString(encryptedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Encrypted message with THUMBPRINT_IDENTIFIER:");
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains("#ThumbprintSHA1"));

        LOG.info("After Encrypting ThumbprintSHA1....");
        WSHandlerResult results = verify(encryptedDoc, encCrypto, keystoreCallbackHandler);

        WSSecurityEngineResult actionResult =
                results.getActionResults().get(WSConstants.ENCR).get(0);
        assertNotNull(actionResult.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE));
        assertNotNull(actionResult.get(WSSecurityEngineResult.TAG_X509_REFERENCE_TYPE));
        REFERENCE_TYPE referenceType =
            (REFERENCE_TYPE)actionResult.get(WSSecurityEngineResult.TAG_X509_REFERENCE_TYPE);
        assertTrue(referenceType == REFERENCE_TYPE.THUMBPRINT_SHA1);
    }

    /**
     * Test that encrypts and decrypts a WS-Security envelope.
     * The test uses the EncryptedKeySHA1 key identifier type.
     * <p/>
     *
     * @throws Exception Thrown when there is any problem in encryption or decryption
     */
    @Test
    public void testX509EncryptionSHA1() throws Exception {
        Crypto encCrypto = CryptoFactory.getInstance();
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecEncrypt builder = new WSSecEncrypt(secHeader);
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.ENCRYPTED_KEY_SHA1_IDENTIFIER);

        LOG.info("Before Encrypting EncryptedKeySHA1....");
        KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.AES_128);
        SecretKey symmetricKey = keyGen.generateKey();
        Document encryptedDoc = builder.build(encCrypto, symmetricKey);

        String outputString =
            XMLUtils.prettyDocumentToString(encryptedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Encrypted message with ENCRYPTED_KEY_SHA1_IDENTIFIER:");
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains("#EncryptedKeySHA1"));

        LOG.info("After Encrypting EncryptedKeySHA1....");
        verify(encryptedDoc, encCrypto, keystoreCallbackHandler);
    }


    /**
     * Test that encrypts a WS-Security envelope.
     * The test uses the X509_SKI key identifier type.
     */
    @Test
    public void testEncryptionX509SKI() throws Exception {
        Crypto encCrypto = CryptoFactory.getInstance("wss-ecdh.properties");

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecEncrypt builder = new WSSecEncrypt(secHeader);
        builder.setUserInfo("secp256r1");
        builder.setKeyEncAlgo(WSConstants.KEYWRAP_AES128);
        builder.setKeyAgreementMethod(WSConstants.AGREEMENT_METHOD_ECDH_ES);
        builder.setKeyDerivationMethod(WSConstants.KEYDERIVATION_CONCATKDF);
        builder.setDigestAlgorithm(WSS4JConstants.SHA256);
        builder.setKeyIdentifierType(WSConstants.X509_SKI);

        LOG.info("Before Encrypting X509SKI");
        KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.AES_128_GCM);
        SecretKey symmetricKey = keyGen.generateKey();

        Document encryptedDoc = builder.build(encCrypto, symmetricKey);
        LOG.info("After Encrypting X509SKI");

        String outputString =
                XMLUtils.prettyDocumentToString(encryptedDoc);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Encrypted message with X509SKI:");
            LOG.debug(outputString);
        }

        assertTrue(outputString.contains("X509Data"));
        assertTrue(outputString.contains("X509SKI"));

        RequestData data = new RequestData();
        data.setCallbackHandler(keystoreCallbackHandler);
        data.setDecCrypto(encCrypto);
        data.setIgnoredBSPRules(Collections.singletonList(BSPRule.R5426));
        new WSSecurityEngine().processSecurityHeader(encryptedDoc, data);
    }

    /**
     * Test that encrypts using EncryptedKeySHA1, where it uses a symmetric key, rather than a
     * generated session key which is then encrypted using a public key.
     *
     * @throws Exception Thrown when there is any problem in encryption or decryption
     */
    @Test
    public void testEncryptionSHA1Symmetric() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecEncrypt builder = new WSSecEncrypt(secHeader);
        builder.setKeyIdentifierType(WSConstants.ENCRYPTED_KEY_SHA1_IDENTIFIER);
        builder.setEncryptSymmKey(false);

        LOG.info("Before Encrypting EncryptedKeySHA1....");
        Document encryptedDoc = builder.build(crypto, key);

        byte[] encodedBytes = KeyUtils.generateDigest(keyData);
        String identifier = org.apache.xml.security.utils.XMLUtils.encodeToString(encodedBytes);
        secretKeyCallbackHandler.addSecretKey(identifier, keyData);

        String outputString =
            XMLUtils.prettyDocumentToString(encryptedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Encrypted message with ENCRYPTED_KEY_SHA1_IDENTIFIER:");
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains("#EncryptedKeySHA1"));

        LOG.info("After Encrypting EncryptedKeySHA1....");
        verify(encryptedDoc, null, secretKeyCallbackHandler);
    }

    /**
     * Test that encrypts using EncryptedKeySHA1, where it uses a symmetric key, rather than a
     * generated session key which is then encrypted using a public key. The request is generated
     * using WSHandler, instead of coding it.
     *
     * @throws Exception Thrown when there is any problem in encryption or decryption
     */
    @Test
    public void testEncryptionSHA1SymmetricBytesHandler() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        java.util.Map<String, Object> messageContext = new java.util.TreeMap<>();
        messageContext.put(WSHandlerConstants.ENC_SYM_ENC_KEY, "false");
        messageContext.put(WSHandlerConstants.ENC_KEY_ID, "EncryptedKeySHA1");
        secretKeyCallbackHandler.setOutboundSecret(keyData);
        messageContext.put(WSHandlerConstants.PW_CALLBACK_REF, secretKeyCallbackHandler);
        reqData.setMsgContext(messageContext);
        reqData.setUsername("");

        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        HandlerAction action = new HandlerAction(WSConstants.ENCR);
        handler.send(
            doc,
            reqData,
            Collections.singletonList(action),
            true
        );

        String outputString =
            XMLUtils.prettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }

        verify(doc, null, secretKeyCallbackHandler);
    }

    /**
     * Test that encrypt and decrypt a WS-Security envelope.
     *
     * This test uses the RSA_15 algorithm to transport (wrap) the symmetric key.
     * The test case creates a ReferenceList element that references EncryptedData
     * elements. The ReferencesList element is put into the Security header, not
     * as child of the EncryptedKey. The EncryptedData elements contain a KeyInfo
     * that references the EncryptedKey via a STR/Reference structure.
     *
     * Refer to OASIS WS Security spec 1.1, chap 7.7
     */
    @Test
    public void testEncryptionDecryptionRSA15STR() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecEncrypt builder = new WSSecEncrypt(secHeader);
        builder.setUserInfo("wss40");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        builder.setSymmetricEncAlgorithm(WSConstants.TRIPLE_DES);
        LOG.info("Before Encryption Triple DES....");

        /*
         * Prepare the Encrypt object with the token, setup data structure
         */
        KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.TRIPLE_DES);
        SecretKey symmetricKey = keyGen.generateKey();
        builder.prepare(crypto, symmetricKey);

        /*
         * Set up the parts structure to encrypt the body
         */
        SOAPConstants soapConstants = XMLUtils.getSOAPConstants(doc
                .getDocumentElement());
        WSEncryptionPart encP = new WSEncryptionPart(soapConstants
                .getBodyQName().getLocalPart(), soapConstants.getEnvelopeURI(),
                "Content");
        builder.getParts().add(encP);

        /*
         * Encrypt the parts (Body), create EncryptedData elements that reference
         * the EncryptedKey, and get a ReferenceList that can be put into the
         * Security header. Be sure that the ReferenceList is after the
         * EncryptedKey element in the Security header (strict layout)
         */
        Element refs = builder.encrypt(symmetricKey);
        builder.addExternalRefElement(refs);

        /*
         * now add (prepend) the EncryptedKey element, then a
         * BinarySecurityToken if one was setup during prepare
         */
        builder.prependToHeader();

        builder.prependBSTElementToHeader();

        Document encryptedDoc = doc;
        LOG.info("After Encryption Triple DES....");

        String outputString =
            XMLUtils.prettyDocumentToString(encryptedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Encrypted message, RSA-15 keytransport, 3DES:");
            LOG.debug(outputString);
        }
        assertFalse(outputString.contains("counter_port_type"));
        WSHandlerResult results = verify(encryptedDoc, crypto, keystoreCallbackHandler);

        outputString =
            XMLUtils.prettyDocumentToString(encryptedDoc);
        assertTrue(outputString.contains("counter_port_type"));

        WSSecurityEngineResult actionResult =
                results.getActionResults().get(WSConstants.ENCR).get(0);
        assertNotNull(actionResult.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE));
        assertNotNull(actionResult.get(WSSecurityEngineResult.TAG_X509_REFERENCE_TYPE));
        REFERENCE_TYPE referenceType =
            (REFERENCE_TYPE)actionResult.get(WSSecurityEngineResult.TAG_X509_REFERENCE_TYPE);
        assertTrue(referenceType == REFERENCE_TYPE.DIRECT_REF);
    }


    @Test
    public void testBadAttribute() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecEncrypt builder = new WSSecEncrypt(secHeader);
        builder.setUserInfo("wss40");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        builder.setSymmetricEncAlgorithm(WSConstants.TRIPLE_DES);

        /*
         * Prepare the Encrypt object with the token, setup data structure
         */
        KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.TRIPLE_DES);
        SecretKey symmetricKey = keyGen.generateKey();
        builder.prepare(crypto, symmetricKey);

        /*
         * Set up the parts structure to encrypt the body
         */
        SOAPConstants soapConstants = XMLUtils.getSOAPConstants(doc
                .getDocumentElement());
        java.util.List<WSEncryptionPart> parts = new ArrayList<>();
        WSEncryptionPart encP = new WSEncryptionPart(soapConstants
                .getBodyQName().getLocalPart(), soapConstants.getEnvelopeURI(),
                "Content");
        parts.add(encP);

        /*
         * Encrypt the parts (Body), create EncryptedData elements that reference
         * the EncryptedKey, and get a ReferenceList that can be put into the
         * Security header. Be sure that the ReferenceList is after the
         * EncryptedKey element in the Security header (strict layout)
         */
        Element refs = builder.encrypt(symmetricKey);
        builder.addExternalRefElement(refs);

        /*
         * now add (prepend) the EncryptedKey element, then a
         * BinarySecurityToken if one was setup during prepare
         */
        Element encryptedKeyElement = builder.getEncryptedKeyElement();
        encryptedKeyElement.setAttributeNS(null, "Type", "SomeType");
        XMLUtils.prependChildElement(secHeader.getSecurityHeaderElement(), encryptedKeyElement);

        builder.prependBSTElementToHeader();

        Document encryptedDoc = doc;

        String outputString =
            XMLUtils.prettyDocumentToString(encryptedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }

        WSSecurityEngine newEngine = new WSSecurityEngine();
        try {
            newEngine.processSecurityHeader(encryptedDoc, null, keystoreCallbackHandler, crypto);
            fail("Failure expected on a bad attribute type");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY);
        }

        RequestData data = new RequestData();
        data.setCallbackHandler(keystoreCallbackHandler);
        data.setDecCrypto(crypto);
        data.setIgnoredBSPRules(Collections.singletonList(BSPRule.R3209));
        newEngine.processSecurityHeader(encryptedDoc, data);
    }

    /**
     * In this test an EncryptedKey structure is embedded in the EncryptedData structure.
     * The EncryptedKey structure refers to a certificate via the SKI_KEY_IDENTIFIER.
     */
    @Test
    public void testEmbeddedEncryptedKey() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecEncrypt builder = new WSSecEncrypt(secHeader);
        builder.setUserInfo("wss40");
        builder.setKeyIdentifierType(WSConstants.SKI_KEY_IDENTIFIER);
        builder.setSymmetricEncAlgorithm(WSConstants.AES_128);

        KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.AES_128);
        SecretKey symmetricKey = keyGen.generateKey();
        builder.prepare(crypto, symmetricKey);
        builder.setEmbedEncryptedKey(true);

        SOAPConstants soapConstants = XMLUtils.getSOAPConstants(doc
                .getDocumentElement());
        java.util.List<WSEncryptionPart> parts = new ArrayList<>();
        WSEncryptionPart encP = new WSEncryptionPart(soapConstants
                .getBodyQName().getLocalPart(), soapConstants.getEnvelopeURI(),
                "Content");
        parts.add(encP);

        builder.encrypt(symmetricKey);

        String outputString =
            XMLUtils.prettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }

        verify(doc, crypto, keystoreCallbackHandler);
    }

    /**
     * Test that encrypt and decrypt a WS-Security envelope.
     * This test uses the RSA OAEP algorithm to transport (wrap) the symmetric
     * key and SHA-256.
     * <p/>
     *
     * @throws Exception Thrown when there is any problem in signing or verification
     */
    @Test
    public void testEncryptionDecryptionOAEPSHA256() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecEncrypt builder = new WSSecEncrypt(secHeader);
        builder.setUserInfo("wss40");
        builder.setKeyEncAlgo(WSConstants.KEYTRANSPORT_RSAOAEP);
        builder.setDigestAlgorithm(WSConstants.SHA256);

        LOG.info("Before Encryption Triple DES/RSA-OAEP....");
        KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.AES_128);
        SecretKey symmetricKey = keyGen.generateKey();
        Document encryptedDoc = builder.build(crypto, symmetricKey);
        LOG.info("After Encryption Triple DES/RSA-OAEP....");

        String outputString =
            XMLUtils.prettyDocumentToString(encryptedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Encrypted message, RSA-OAEP keytransport, 3DES:");
            LOG.debug(outputString);
        }
        assertFalse(outputString.contains("counter_port_type"));

        WSSecurityEngine newEngine = new WSSecurityEngine();
        WSHandlerResult results =
            newEngine.processSecurityHeader(encryptedDoc, null, keystoreCallbackHandler, crypto);

        WSSecurityEngineResult actionResult =
                results.getActionResults().get(WSConstants.ENCR).get(0);
        assertNotNull(actionResult);
    }

    // CN has a "*" in it
    @Test
    public void testEncryptionWithRegexpCert() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecEncrypt builder = new WSSecEncrypt(secHeader);
        builder.setUserInfo("regexp");
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        builder.setKeyEncAlgo(WSConstants.KEYTRANSPORT_RSAOAEP);
        LOG.info("Before Encryption Triple DES/RSA-OAEP....");

        Crypto regexpCrypto = CryptoFactory.getInstance("regexp.properties");
        KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.AES_128);
        SecretKey symmetricKey = keyGen.generateKey();
        Document encryptedDoc = builder.build(regexpCrypto, symmetricKey);
        LOG.info("After Encryption Triple DES/RSA-OAEP....");

        String outputString =
            XMLUtils.prettyDocumentToString(encryptedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Encrypted message, RSA-OAEP keytransport, 3DES:");
            LOG.debug(outputString);
        }
        assertFalse(outputString.contains("counter_port_type"));

        WSSecurityEngine newEngine = new WSSecurityEngine();
        newEngine.processSecurityHeader(encryptedDoc, null, keystoreCallbackHandler, regexpCrypto);
    }

    /**
     * Verifies the soap envelope <p/>
     *
     * @param doc
     * @param decCrypto
     * @param handler
     * @throws Exception
     *             Thrown when there is a problem in verification
     */
    private WSHandlerResult verify(
        Document doc, Crypto decCrypto, CallbackHandler handler
    ) throws Exception {
        WSHandlerResult results =
            secEngine.processSecurityHeader(doc, null, handler, decCrypto);
        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        return results;
    }

    /**
     * Verifies the soap envelope
     * <p/>
     *
     * @param doc
     * @param handler
     * @param expectedEncryptedElement
     * @throws Exception Thrown when there is a problem in verification
     */
    @SuppressWarnings("unchecked")
    private WSHandlerResult verify(
        Document doc,
        CallbackHandler handler,
        javax.xml.namespace.QName expectedEncryptedElement
    ) throws Exception {
        final WSHandlerResult results =
            secEngine.processSecurityHeader(doc, null, handler, null, crypto);
        String outputString =
            XMLUtils.prettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        assertTrue(outputString.indexOf("counter_port_type") > 0 ? true : false);
        //
        // walk through the results, and make sure there is an encryption
        // action, together with a reference to the decrypted element
        // (as a QName)
        //
        boolean encrypted = false;
        for (WSSecurityEngineResult result : results.getResults()) {
            final Integer action = (Integer) result.get(WSSecurityEngineResult.TAG_ACTION);
            assertNotNull(action);
            if ((action & WSConstants.ENCR) != 0) {
                final java.util.List<WSDataRef> refs =
                    (java.util.List<WSDataRef>) result.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
                assertNotNull(refs);
                encrypted = true;
                for (WSDataRef ref : refs) {
                    assertNotNull(ref.getName());
                    assertEquals(
                        expectedEncryptedElement,
                        ref.getName()
                    );
                    assertNotNull(ref.getProtectedElement());
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("WSDataRef element: ");
                        LOG.debug(
                            DOM2Writer.nodeToString(ref.getProtectedElement())
                        );
                    }
                }
            }
        }
        assertTrue(encrypted);
        return results;
    }

}
