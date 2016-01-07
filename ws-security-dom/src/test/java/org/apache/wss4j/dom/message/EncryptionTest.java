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

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.callback.CallbackHandler;

import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.DOM2Writer;
import org.apache.wss4j.common.util.KeyUtils;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.SOAPConstants;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSDataRef;
import org.apache.wss4j.dom.common.CustomHandler;
import org.apache.wss4j.dom.common.KeystoreCallbackHandler;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.common.SecretKeyCallbackHandler;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.HandlerAction;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.dom.str.STRParser.REFERENCE_TYPE;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.apache.xml.security.utils.Base64;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * A set of test-cases for encrypting and decrypting SOAP requests.
 */
public class EncryptionTest extends org.junit.Assert {
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
    private Crypto crypto = null;

    @org.junit.AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }

    public EncryptionTest() throws Exception {
        crypto = CryptoFactory.getInstance("wss40.properties");
    }

    /**
     * Setup method
     *
     * @throws java.lang.Exception Thrown when there is a problem in setup
     */
    @Before
    public void setUp() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        key = keyGen.generateKey();
        keyData = key.getEncoded();
        secEngine.setWssConfig(WSSConfig.getNewInstance());
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
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setUserInfo("wss40");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        builder.setSymmetricEncAlgorithm(WSConstants.TRIPLE_DES);
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        LOG.info("Before Encryption Triple DES....");
        Document encryptedDoc = builder.build(doc, crypto, secHeader);
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
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        builder.setSymmetricEncAlgorithm(WSConstants.AES_128);
        builder.setSymmetricKey(null);

        WSEncryptionPart encP =
            new WSEncryptionPart(
                "add", "http://ws.apache.org/counter/counter_port_type", "Element"
            );
        builder.getParts().add(encP);

        doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        LOG.info("Before Encryption AES 128/RSA-15....");
        encryptedDoc = builder.build(doc, crypto, secHeader);
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
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setUserInfo("wss40");
        builder.setKeyIdentifierType(WSConstants.X509_KEY_IDENTIFIER);
        builder.setKeyEncAlgo(WSConstants.KEYTRANSPORT_RSAOEP);
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        LOG.info("Before Encryption Triple DES/RSA-OAEP....");
        Document encryptedDoc = builder.build(doc, crypto, secHeader);
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
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setKeyIdentifierType(WSConstants.KEY_VALUE);
        builder.setKeyEncAlgo(WSConstants.KEYTRANSPORT_RSAOEP);
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("wss40");
        X509Certificate[] certs = crypto.getX509Certificates(cryptoType);
        assertNotNull(certs);
        builder.setUseThisPublicKey(certs[0].getPublicKey());
        
        Document encryptedDoc = builder.build(doc, crypto, secHeader);

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
        Crypto encCrypto = CryptoFactory.getInstance();
        WSSecEncrypt encrypt = new WSSecEncrypt();
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e");
        LOG.info("Before Encryption....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        Document encryptedDoc = encrypt.build(doc, encCrypto, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("After the first encryption:");
            String outputString =
                XMLUtils.prettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }

        Document encryptedEncryptedDoc = encrypt.build(encryptedDoc, encCrypto, secHeader);

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
     * Test that encrypts and decrypts a WS-Security envelope.
     * The test uses the ThumbprintSHA1 key identifier type.
     * <p/>
     *
     * @throws java.lang.Exception Thrown when there is any problem in encryption or decryption
     */
    @Test
    public void testX509EncryptionThumb() throws Exception {
        Crypto encCrypto = CryptoFactory.getInstance();
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);

        LOG.info("Before Encrypting ThumbprintSHA1....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        Document encryptedDoc = builder.build(doc, encCrypto, secHeader);

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
     * @throws java.lang.Exception Thrown when there is any problem in encryption or decryption
     */
    @Test
    public void testX509EncryptionSHA1() throws Exception {
        Crypto encCrypto = CryptoFactory.getInstance();
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.ENCRYPTED_KEY_SHA1_IDENTIFIER);

        LOG.info("Before Encrypting EncryptedKeySHA1....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        Document encryptedDoc = builder.build(doc, encCrypto, secHeader);

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
     * Test that encrypts using EncryptedKeySHA1, where it uses a symmetric key, rather than a
     * generated session key which is then encrypted using a public key.
     *
     * @throws java.lang.Exception Thrown when there is any problem in encryption or decryption
     */
    @Test
    public void testEncryptionSHA1Symmetric() throws Exception {
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setKeyIdentifierType(WSConstants.ENCRYPTED_KEY_SHA1_IDENTIFIER);
        builder.setSymmetricKey(key);
        builder.setEncryptSymmKey(false);

        LOG.info("Before Encrypting EncryptedKeySHA1....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        Document encryptedDoc = builder.build(doc, crypto, secHeader);

        byte[] encodedBytes = KeyUtils.generateDigest(keyData);
        String identifier = Base64.encode(encodedBytes);
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
     * Test that encrypts using EncryptedKeySHA1, where it uses a symmetric key (bytes),
     * rather than a generated session key which is then encrypted using a public key.
     *
     * @throws java.lang.Exception Thrown when there is any problem in encryption or decryption
     */
    @Test
    public void testEncryptionSHA1SymmetricBytes() throws Exception {
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setKeyIdentifierType(WSConstants.ENCRYPTED_KEY_SHA1_IDENTIFIER);
        builder.setEphemeralKey(keyData);
        builder.setEncryptSymmKey(false);

        LOG.info("Before Encrypting EncryptedKeySHA1....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        Document encryptedDoc = builder.build(doc, crypto, secHeader);

        byte[] encodedBytes = KeyUtils.generateDigest(keyData);
        String identifier = Base64.encode(encodedBytes);
        secretKeyCallbackHandler.addSecretKey(identifier, keyData);

        String outputString =
            XMLUtils.prettyDocumentToString(encryptedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Encrypted message with ENCRYPTED_KEY_SHA1_IDENTIFIER:");
            LOG.debug(outputString);
        }
        assertTrue(outputString.contains("#EncryptedKeySHA1"));

        LOG.info("After Encrypting EncryptedKeySHA1....");
        verify(encryptedDoc, crypto, secretKeyCallbackHandler);
    }


    /**
     * Test that encrypts using EncryptedKeySHA1, where it uses a symmetric key, rather than a
     * generated session key which is then encrypted using a public key. The request is generated
     * using WSHandler, instead of coding it.
     *
     * @throws java.lang.Exception Thrown when there is any problem in encryption or decryption
     */
    @Test
    public void testEncryptionSHA1SymmetricBytesHandler() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        java.util.Map<String, Object> messageContext = new java.util.TreeMap<String, Object>();
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
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setUserInfo("wss40");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        builder.setSymmetricEncAlgorithm(WSConstants.TRIPLE_DES);
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        LOG.info("Before Encryption Triple DES....");

        /*
         * Prepare the Encrypt object with the token, setup data structure
         */
        builder.prepare(doc, crypto);

        /*
         * Set up the parts structure to encrypt the body
         */
        SOAPConstants soapConstants = WSSecurityUtil.getSOAPConstants(doc
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
        Element refs = builder.encrypt();
        builder.addExternalRefElement(refs, secHeader);

        /*
         * now add (prepend) the EncryptedKey element, then a
         * BinarySecurityToken if one was setup during prepare
         */
        builder.prependToHeader(secHeader);

        builder.prependBSTElementToHeader(secHeader);

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
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setUserInfo("wss40");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        builder.setSymmetricEncAlgorithm(WSConstants.TRIPLE_DES);
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        /*
         * Prepare the Encrypt object with the token, setup data structure
         */
        builder.prepare(doc, crypto);

        /*
         * Set up the parts structure to encrypt the body
         */
        SOAPConstants soapConstants = WSSecurityUtil.getSOAPConstants(doc
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
        Element refs = builder.encrypt();
        builder.addExternalRefElement(refs, secHeader);

        /*
         * now add (prepend) the EncryptedKey element, then a
         * BinarySecurityToken if one was setup during prepare
         */
        Element encryptedKeyElement = builder.getEncryptedKeyElement();
        encryptedKeyElement.setAttributeNS(null, "Type", "SomeType");
        WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), encryptedKeyElement);

        builder.prependBSTElementToHeader(secHeader);

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

        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setUserInfo("wss40");
        builder.setKeyIdentifierType(WSConstants.SKI_KEY_IDENTIFIER);
        builder.setSymmetricEncAlgorithm(WSConstants.AES_128);
        builder.prepare(doc, crypto);
        builder.setEmbedEncryptedKey(true);

        SOAPConstants soapConstants = WSSecurityUtil.getSOAPConstants(doc
                .getDocumentElement());
        java.util.List<WSEncryptionPart> parts = new ArrayList<>();
        WSEncryptionPart encP = new WSEncryptionPart(soapConstants
                .getBodyQName().getLocalPart(), soapConstants.getEnvelopeURI(),
                "Content");
        parts.add(encP);

        builder.encrypt();

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
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setUserInfo("wss40");
        builder.setKeyEncAlgo(WSConstants.KEYTRANSPORT_RSAOEP);
        builder.setDigestAlgorithm(WSConstants.SHA256);
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        LOG.info("Before Encryption Triple DES/RSA-OAEP....");
        Document encryptedDoc = builder.build(doc, crypto, secHeader);
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
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setUserInfo("regexp");
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        builder.setKeyEncAlgo(WSConstants.KEYTRANSPORT_RSAOEP);
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        LOG.info("Before Encryption Triple DES/RSA-OAEP....");

        Crypto regexpCrypto = CryptoFactory.getInstance("regexp.properties");
        Document encryptedDoc = builder.build(doc, regexpCrypto, secHeader);
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
     * @param envelope
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
     * @param envelope
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
        for (java.util.Iterator<WSSecurityEngineResult> ipos = results.getResults().iterator();
            ipos.hasNext();) {
            final WSSecurityEngineResult result = ipos.next();
            final Integer action = (Integer) result.get(WSSecurityEngineResult.TAG_ACTION);
            assertNotNull(action);
            if ((action & WSConstants.ENCR) != 0) {
                final java.util.List<WSDataRef> refs =
                    (java.util.List<WSDataRef>) result.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
                assertNotNull(refs);
                encrypted = true;
                for (java.util.Iterator<WSDataRef> jpos = refs.iterator(); jpos.hasNext();) {
                    final WSDataRef ref = jpos.next();
                    assertNotNull(ref);
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
