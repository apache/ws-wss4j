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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Collections;

import javax.security.auth.callback.CallbackHandler;

import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.token.SecurityTokenReference;
import org.apache.wss4j.common.util.UsernameTokenUtil;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.common.EncodedPasswordCallbackHandler;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.dom.common.UsernamePasswordCallbackHandler;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.dom.message.token.UsernameToken;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.apache.xml.security.utils.Base64;
import org.junit.Test;
import org.w3c.dom.Document;

/**
 * WS-Security Test Case for UsernameToken Key Derivation, as defined in the
 * UsernameTokenProfile 1.1 specification. The derived keys are used to encrypt
 * and sign, as per wsc:DerivedKeyToken.
 */
public class UTDerivedKeyTest extends org.junit.Assert {
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(UTDerivedKeyTest.class);
    private CallbackHandler callbackHandler = new UsernamePasswordCallbackHandler();
    private Crypto crypto = null;

    @org.junit.AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }

    public UTDerivedKeyTest() throws Exception {
        crypto = CryptoFactory.getInstance();
    }

    /**
     * Unit test for the UsernameToken derived key functionality
     */
    @Test
    public void testUsernameTokenUnit() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        UsernameToken usernameToken = new UsernameToken(true, doc, null);
        usernameToken.setName("bob");

        byte[] salt = usernameToken.addSalt(doc, null, false);
        assertTrue(salt.length == 16);
        assertTrue(salt[0] == 0x02);
        byte[] utSalt = usernameToken.getSalt();
        assertTrue(salt.length == utSalt.length);
        for (int i = 0; i < salt.length; i++) {
            assertTrue(salt[i] == utSalt[i]);
        }

        usernameToken.addIteration(doc, 500);
        assertTrue(usernameToken.getIteration() == 500);

        WSSecurityUtil.prependChildElement(
            secHeader.getSecurityHeader(), usernameToken.getElement()
        );

        String outputString =
            XMLUtils.PrettyDocumentToString(doc);
        assertTrue(outputString.contains("wsse:Username"));
        assertFalse(outputString.contains("wsse:Password"));
        assertTrue(outputString.contains("wsse11:Salt"));
        assertTrue(outputString.contains("wsse11:Iteration"));

        byte[] derivedKey = UsernameTokenUtil.generateDerivedKey("security", salt, 500);
        assertTrue(derivedKey.length == 20);

        // "c2VjdXJpdHk=" is the Base64 encoding of "security"
        derivedKey = UsernameTokenUtil.generateDerivedKey(Base64.decode("c2VjdXJpdHk="), salt, 500);
        assertTrue(derivedKey.length == 20);
    }

    /**
     * Test for encoded passwords.
     */
    @Test
    public void testDerivedKeyWithEncodedPasswordBaseline() throws Exception {
        String password = "password";
        // The SHA-1 of the password is known as a password equivalent in the UsernameToken specification.
        byte[] passwordHash = MessageDigest.getInstance("SHA-1").digest(password.getBytes(StandardCharsets.UTF_8));

        byte[] salt = Base64.decode("LKpycbfgRzwDnBz6kkhAAQ==");
        int iteration = 1049;
        byte[] expectedDerivedKey = Base64.decode("C7Ll/OY4TECb6hZuMMiX/5hzszo=");
        byte[] derivedKey = UsernameTokenUtil.generateDerivedKey(passwordHash, salt, iteration);
        assertTrue("the derived key is not as expected", Arrays.equals(expectedDerivedKey, derivedKey));
    }

    /**
     * Test using a UsernameToken derived key for encrypting a SOAP body
     */
    @Test
    public void testDerivedKeyEncryption() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setUserInfo("bob", "security");
        builder.addDerivedKey(false, null, 1000);
        builder.prepare(doc);

        byte[] derivedKey = builder.getDerivedKey();
        assertTrue(derivedKey.length == 20);

        String tokenIdentifier = builder.getId();

        //
        // Derived key encryption
        //
        WSSecDKEncrypt encrBuilder = new WSSecDKEncrypt();
        encrBuilder.setSymmetricEncAlgorithm(WSConstants.AES_128);
        encrBuilder.setExternalKey(derivedKey, tokenIdentifier);
        encrBuilder.setCustomValueType(WSConstants.WSS_USERNAME_TOKEN_VALUE_TYPE);
        Document encryptedDoc = encrBuilder.build(doc, secHeader);

        builder.prependToHeader(secHeader);

        String outputString =
            XMLUtils.PrettyDocumentToString(encryptedDoc);
        assertTrue(outputString.contains("wsse:Username"));
        assertFalse(outputString.contains("wsse:Password"));
        assertTrue(outputString.contains("wsse11:Salt"));
        assertTrue(outputString.contains("wsse11:Iteration"));
        assertFalse(outputString.contains("testMethod"));
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }

        verify(encryptedDoc);

        try {
            verify(encryptedDoc, false);
            fail("Failure expected on deriving keys from a UsernameToken not allowed");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
        }
    }

    /**
     * Test using a UsernameToken derived key for encrypting a SOAP body
     */
    @Test
    public void testDerivedKeyEncryptionWithEncodedPassword() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setPasswordsAreEncoded(true);
        builder.setUserInfo("bob", Base64.encode(MessageDigest.getInstance("SHA-1").digest("security".getBytes(StandardCharsets.UTF_8))));
        builder.addDerivedKey(false, null, 1000);
        builder.prepare(doc);

        byte[] derivedKey = builder.getDerivedKey();
        assertTrue(derivedKey.length == 20);
        String tokenIdentifier = builder.getId();

        //
        // Derived key encryption
        //
        WSSecDKEncrypt encrBuilder = new WSSecDKEncrypt();
        encrBuilder.setSymmetricEncAlgorithm(WSConstants.AES_128);
        encrBuilder.setExternalKey(derivedKey, tokenIdentifier);
        encrBuilder.setCustomValueType(WSConstants.WSS_USERNAME_TOKEN_VALUE_TYPE);
        Document encryptedDoc = encrBuilder.build(doc, secHeader);

        builder.prependToHeader(secHeader);

        String outputString =
            XMLUtils.PrettyDocumentToString(encryptedDoc);
        assertTrue(outputString.contains("wsse:Username"));
        assertFalse(outputString.contains("wsse:Password"));
        assertTrue(outputString.contains("wsse11:Salt"));
        assertTrue(outputString.contains("wsse11:Iteration"));
        assertFalse(outputString.contains("testMethod"));
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }

        RequestData requestData = new RequestData();
        requestData.setEncodePasswords(true);
        requestData.setAllowUsernameTokenNoPassword(true);
        requestData.setCallbackHandler(new EncodedPasswordCallbackHandler());

        WSSecurityEngine newEngine = new WSSecurityEngine();
        newEngine.processSecurityHeader(encryptedDoc, requestData);
    }

    /**
     * Test using a UsernameToken derived key for encrypting a SOAP body. In this test the
     * derived key is modified before encryption, and so decryption should fail.
     */
    @Test
    public void testDerivedKeyChangedEncryption() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setUserInfo("bob", "security");
        builder.addDerivedKey(false, null, 1000);
        builder.prepare(doc);

        byte[] derivedKey = builder.getDerivedKey();
        derivedKey[5] = 'z';
        derivedKey[6] = 'a';
        assertTrue(derivedKey.length == 20);

        String tokenIdentifier = builder.getId();

        //
        // Derived key encryption
        //
        WSSecDKEncrypt encrBuilder = new WSSecDKEncrypt();
        encrBuilder.setSymmetricEncAlgorithm(WSConstants.AES_128);
        encrBuilder.setExternalKey(derivedKey, tokenIdentifier);
        encrBuilder.setCustomValueType(WSConstants.WSS_USERNAME_TOKEN_VALUE_TYPE);
        Document encryptedDoc = encrBuilder.build(doc, secHeader);

        builder.prependToHeader(secHeader);

        String outputString =
            XMLUtils.PrettyDocumentToString(encryptedDoc);
        assertTrue(outputString.contains("wsse:Username"));
        assertFalse(outputString.contains("wsse:Password"));
        assertTrue(outputString.contains("wsse11:Salt"));
        assertTrue(outputString.contains("wsse11:Iteration"));
        assertFalse(outputString.contains("testMethod"));
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }

        try {
            verify(encryptedDoc);
            fail("Failure expected on a bad derived encryption");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.FAILED_CHECK);
        }
    }

    /**
     * Test using a UsernameToken derived key for encrypting a SOAP body. In this test the
     * user is "colm" rather than "bob", and so decryption should fail.
     */
    @Test
    public void testDerivedKeyBadUserEncryption() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setUserInfo("colm", "security");
        builder.addDerivedKey(false, null, 1000);
        builder.prepare(doc);

        byte[] derivedKey = builder.getDerivedKey();
        assertTrue(derivedKey.length == 20);

        String tokenIdentifier = builder.getId();

        //
        // Derived key encryption
        //
        WSSecDKEncrypt encrBuilder = new WSSecDKEncrypt();
        encrBuilder.setSymmetricEncAlgorithm(WSConstants.AES_128);
        encrBuilder.setExternalKey(derivedKey, tokenIdentifier);
        encrBuilder.setCustomValueType(WSConstants.WSS_USERNAME_TOKEN_VALUE_TYPE);
        Document encryptedDoc = encrBuilder.build(doc, secHeader);

        builder.prependToHeader(secHeader);

        String outputString =
            XMLUtils.PrettyDocumentToString(encryptedDoc);
        assertTrue(outputString.contains("wsse:Username"));
        assertFalse(outputString.contains("wsse:Password"));
        assertTrue(outputString.contains("wsse11:Salt"));
        assertTrue(outputString.contains("wsse11:Iteration"));
        assertFalse(outputString.contains("testMethod"));
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }

        try {
            verify(encryptedDoc);
            fail("Failure expected on a bad derived encryption");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
        }
    }

    /**
     * Test using a UsernameToken derived key for signing a SOAP body
     */
    @Test
    public void testDerivedKeySignature() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setUserInfo("bob", "security");
        builder.addDerivedKey(true, null, 1000);
        builder.prepare(doc);

        byte[] derivedKey = builder.getDerivedKey();
        assertTrue(derivedKey.length == 20);

        String tokenIdentifier = builder.getId();

        //
        // Derived key signature
        //
        WSSecDKSign sigBuilder = new WSSecDKSign();
        sigBuilder.setExternalKey(derivedKey, tokenIdentifier);
        sigBuilder.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
        sigBuilder.setCustomValueType(WSConstants.WSS_USERNAME_TOKEN_VALUE_TYPE);
        Document signedDoc = sigBuilder.build(doc, secHeader);

        builder.prependToHeader(secHeader);

        String outputString =
            XMLUtils.PrettyDocumentToString(signedDoc);
        assertTrue(outputString.contains("wsse:Username"));
        assertFalse(outputString.contains("wsse:Password"));
        assertTrue(outputString.contains("wsse11:Salt"));
        assertTrue(outputString.contains("wsse11:Iteration"));
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }

        WSHandlerResult results = verify(signedDoc);
        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.SIGN).get(0);
        java.security.Principal principal =
            (java.security.Principal) actionResult.get(WSSecurityEngineResult.TAG_PRINCIPAL);
        // System.out.println(principal.getName());
        assertTrue(principal.getName().contains("DK"));
    }

    /**
     * Test using a UsernameToken derived key for signing a SOAP body
     */
    @Test
    public void testDerivedKeySignatureWithEncodedPassword() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setPasswordsAreEncoded(true);
        builder.setUserInfo("bob", Base64.encode(MessageDigest.getInstance("SHA-1").digest("security".getBytes(StandardCharsets.UTF_8))));
        builder.addDerivedKey(true, null, 1000);
        builder.prepare(doc);

        byte[] derivedKey = builder.getDerivedKey();
        assertTrue(derivedKey.length == 20);

        String tokenIdentifier = builder.getId();

        //
        // Derived key signature
        //
        WSSecDKSign sigBuilder = new WSSecDKSign();
        sigBuilder.setExternalKey(derivedKey, tokenIdentifier);
        sigBuilder.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
        sigBuilder.setCustomValueType(WSConstants.WSS_USERNAME_TOKEN_VALUE_TYPE);
        Document signedDoc = sigBuilder.build(doc, secHeader);

        builder.prependToHeader(secHeader);

        String outputString =
            XMLUtils.PrettyDocumentToString(signedDoc);
        assertTrue(outputString.contains("wsse:Username"));
        assertFalse(outputString.contains("wsse:Password"));
        assertTrue(outputString.contains("wsse11:Salt"));
        assertTrue(outputString.contains("wsse11:Iteration"));
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }

        RequestData requestData = new RequestData();
        requestData.setEncodePasswords(true);
        requestData.setAllowUsernameTokenNoPassword(true);
        requestData.setCallbackHandler(new EncodedPasswordCallbackHandler());

        WSSecurityEngine newEngine = new WSSecurityEngine();
        WSHandlerResult results = newEngine.processSecurityHeader(signedDoc, requestData);

        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.SIGN).get(0);
        java.security.Principal principal =
            (java.security.Principal) actionResult.get(WSSecurityEngineResult.TAG_PRINCIPAL);
        // System.out.println(principal.getName());
        assertTrue(principal.getName().contains("DK"));
    }

    /**
     * Test using a UsernameToken derived key for signing a SOAP body. In this test the
     * derived key is modified before signature, and so signature verification should
     * fail.
     */
    @Test
    public void testDerivedKeyChangedSignature() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setUserInfo("bob", "security");
        builder.addDerivedKey(true, null, 1000);
        builder.prepare(doc);

        byte[] derivedKey = builder.getDerivedKey();
        if (derivedKey[5] != 12) {
            derivedKey[5] = 12;
        } else {
            derivedKey[5] = 13;
        }
        assertTrue(derivedKey.length == 20);

        String tokenIdentifier = builder.getId();

        //
        // Derived key signature
        //
        WSSecDKSign sigBuilder = new WSSecDKSign();
        sigBuilder.setExternalKey(derivedKey, tokenIdentifier);
        sigBuilder.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
        sigBuilder.setCustomValueType(WSConstants.WSS_USERNAME_TOKEN_VALUE_TYPE);
        Document signedDoc = sigBuilder.build(doc, secHeader);

        builder.prependToHeader(secHeader);

        String outputString =
            XMLUtils.PrettyDocumentToString(signedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }

        try {
            verify(signedDoc);
            fail("Failure expected on a bad derived signature");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.FAILED_CHECK);
        }
    }

    /**
     * Test using a UsernameToken derived key for signing a SOAP body. In this test the
     * user is "colm" rather than "bob", and so signature verification should fail.
     */
    @Test
    public void testDerivedKeyBadUserSignature() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setUserInfo("colm", "security");
        builder.addDerivedKey(true, null, 1000);
        builder.prepare(doc);

        byte[] derivedKey = builder.getDerivedKey();
        assertTrue(derivedKey.length == 20);

        String tokenIdentifier = builder.getId();

        //
        // Derived key signature
        //
        WSSecDKSign sigBuilder = new WSSecDKSign();
        sigBuilder.setExternalKey(derivedKey, tokenIdentifier);
        sigBuilder.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
        sigBuilder.setCustomValueType(WSConstants.WSS_USERNAME_TOKEN_VALUE_TYPE);
        Document signedDoc = sigBuilder.build(doc, secHeader);

        builder.prependToHeader(secHeader);

        String outputString =
            XMLUtils.PrettyDocumentToString(signedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }

        try {
            verify(signedDoc);
            fail("Failure expected on a bad derived signature");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
        }
    }

    /**
     * Unit test for creating a Username Token with no salt element that is used for
     * deriving a key for encryption.
     */
    @Test
    public void testNoSaltEncryption() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        UsernameToken usernameToken = new UsernameToken(true, doc, null);
        usernameToken.setName("bob");
        WSSConfig config = WSSConfig.getNewInstance();
        usernameToken.setID(config.getIdAllocator().createId("UsernameToken-", usernameToken));

        byte[] salt = UsernameTokenUtil.generateSalt(false);
        usernameToken.addIteration(doc, 1000);

        byte[] derivedKey = UsernameTokenUtil.generateDerivedKey("security", salt, 1000);

        //
        // Derived key encryption
        //
        WSSecDKEncrypt encrBuilder = new WSSecDKEncrypt();
        encrBuilder.setSymmetricEncAlgorithm(WSConstants.AES_128);
        encrBuilder.setExternalKey(derivedKey, usernameToken.getID());
        encrBuilder.setCustomValueType(WSConstants.WSS_USERNAME_TOKEN_VALUE_TYPE);
        Document encryptedDoc = encrBuilder.build(doc, secHeader);

        WSSecurityUtil.prependChildElement(
            secHeader.getSecurityHeader(), usernameToken.getElement()
        );

        String outputString =
            XMLUtils.PrettyDocumentToString(doc);
        assertTrue(outputString.contains("wsse:Username"));
        assertFalse(outputString.contains("wsse:Password"));
        assertFalse(outputString.contains("wsse11:Salt"));
        assertTrue(outputString.contains("wsse11:Iteration"));
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }

        try {
            verify(encryptedDoc);
            fail("Failure expected on no salt element");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.FAILURE);
        }
    }

    /**
     * Unit test for creating a Username Token with no iteration element that is used for
     * deriving a key for encryption.
     */
    @Test
    public void testNoIterationEncryption() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        UsernameToken usernameToken = new UsernameToken(true, doc, null);
        usernameToken.setName("bob");
        WSSConfig config = WSSConfig.getNewInstance();
        usernameToken.setID(config.getIdAllocator().createId("UsernameToken-", usernameToken));

        byte[] salt = usernameToken.addSalt(doc, null, false);
        byte[] derivedKey = UsernameTokenUtil.generateDerivedKey("security", salt, 1000);

        //
        // Derived key encryption
        //
        WSSecDKEncrypt encrBuilder = new WSSecDKEncrypt();
        encrBuilder.setSymmetricEncAlgorithm(WSConstants.AES_128);
        encrBuilder.setExternalKey(derivedKey, usernameToken.getID());
        encrBuilder.setCustomValueType(WSConstants.WSS_USERNAME_TOKEN_VALUE_TYPE);
        Document encryptedDoc = encrBuilder.build(doc, secHeader);

        WSSecurityUtil.prependChildElement(
            secHeader.getSecurityHeader(), usernameToken.getElement()
        );

        String outputString =
            XMLUtils.PrettyDocumentToString(doc);
        assertTrue(outputString.contains("wsse:Username"));
        assertFalse(outputString.contains("wsse:Password"));
        assertTrue(outputString.contains("wsse11:Salt"));
        assertFalse(outputString.contains("wsse11:Iteration"));
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }

        try {
            verify(encryptedDoc);
            fail("Failure expected on no iteration element");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN);
        }
    }

    /**
     * Unit test for creating a Username Token with an iteration value < 1000 that is used for
     * deriving a key for encryption.
     */
    @Test
    public void testLowIterationEncryption() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        UsernameToken usernameToken = new UsernameToken(true, doc, null);
        usernameToken.setName("bob");
        WSSConfig config = WSSConfig.getNewInstance();
        usernameToken.setID(config.getIdAllocator().createId("UsernameToken-", usernameToken));

        usernameToken.addIteration(doc, 500);
        byte[] salt = usernameToken.addSalt(doc, null, false);
        byte[] derivedKey = UsernameTokenUtil.generateDerivedKey("security", salt, 500);

        //
        // Derived key encryption
        //
        WSSecDKEncrypt encrBuilder = new WSSecDKEncrypt();
        encrBuilder.setSymmetricEncAlgorithm(WSConstants.AES_128);
        encrBuilder.setExternalKey(derivedKey, usernameToken.getID());
        encrBuilder.setCustomValueType(WSConstants.WSS_USERNAME_TOKEN_VALUE_TYPE);
        Document encryptedDoc = encrBuilder.build(doc, secHeader);

        WSSecurityUtil.prependChildElement(
            secHeader.getSecurityHeader(), usernameToken.getElement()
        );

        String outputString =
            XMLUtils.PrettyDocumentToString(doc);
        assertTrue(outputString.contains("wsse:Username"));
        assertFalse(outputString.contains("wsse:Password"));
        assertTrue(outputString.contains("wsse11:Salt"));
        assertTrue(outputString.contains("wsse11:Iteration"));
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }

        try {
            verify(encryptedDoc);
            fail("Failure expected on a low iteration value");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY);
        }

        RequestData data = new RequestData();
        data.setCallbackHandler(callbackHandler);
        data.setDecCrypto(crypto);
        data.setIgnoredBSPRules(Collections.singletonList(BSPRule.R4218));
        data.setAllowUsernameTokenNoPassword(true);

        WSSecurityEngine engine = new WSSecurityEngine();
        engine.setWssConfig(config);
        engine.processSecurityHeader(doc, data);
    }


    /**
     * Test using a UsernameToken derived key for encrypting a SOAP body. The Reference to the
     * UsernameToken contains a non-standard value type, which is rejected when the corresponding
     * BSP rule is turned on.
     */
    @Test
    public void testBadValueType() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setUserInfo("bob", "security");
        builder.addDerivedKey(false, null, 1000);
        builder.prepare(doc);

        byte[] derivedKey = builder.getDerivedKey();
        assertTrue(derivedKey.length == 20);

        String tokenIdentifier = builder.getId();

        //
        // Derived key encryption
        //
        WSSecDKEncrypt encrBuilder = new WSSecDKEncrypt();
        encrBuilder.setSymmetricEncAlgorithm(WSConstants.AES_128);
        encrBuilder.setExternalKey(derivedKey, tokenIdentifier);
        encrBuilder.setCustomValueType(WSConstants.WSS_SAML_TOKEN_TYPE);
        Document encryptedDoc = encrBuilder.build(doc, secHeader);

        builder.prependToHeader(secHeader);

        String outputString =
            XMLUtils.PrettyDocumentToString(encryptedDoc);
        assertTrue(outputString.contains("wsse:Username"));
        assertFalse(outputString.contains("wsse:Password"));
        assertTrue(outputString.contains("wsse11:Salt"));
        assertTrue(outputString.contains("wsse11:Iteration"));
        assertFalse(outputString.contains("testMethod"));
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }

        try {
            verify(encryptedDoc);
            fail("Failure expected on a bad value type");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY);
        }

        // Turn off BSP compliance and it should work
        RequestData data = new RequestData();
        data.setCallbackHandler(callbackHandler);
        data.setDecCrypto(crypto);
        data.setAllowUsernameTokenNoPassword(true);

        WSSConfig config = WSSConfig.getNewInstance();
        WSSecurityEngine newEngine = new WSSecurityEngine();
        newEngine.setWssConfig(config);
        data.setIgnoredBSPRules(Collections.singletonList(BSPRule.R4214));
        newEngine.processSecurityHeader(encryptedDoc, data);
    }


    /**
     * Test using a UsernameToken derived key for encrypting a SOAP body. A KeyIdentifier is
     * used to refer to the UsernameToken, which is forbidden by the BSP.
     */
    @Test
    public void testKeyIdentifier() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setUserInfo("bob", "security");
        builder.addDerivedKey(false, null, 1000);
        builder.prepare(doc);

        byte[] derivedKey = builder.getDerivedKey();
        assertTrue(derivedKey.length == 20);

        String tokenIdentifier = builder.getId();

        //
        // Derived key encryption
        //
        WSSecDKEncrypt encrBuilder = new WSSecDKEncrypt();
        encrBuilder.setSymmetricEncAlgorithm(WSConstants.AES_128);

        SecurityTokenReference strEncKey = new SecurityTokenReference(doc);
        strEncKey.setKeyIdentifier(
            WSConstants.WSS_USERNAME_TOKEN_VALUE_TYPE, tokenIdentifier, true
        );
        encrBuilder.setExternalKey(derivedKey, strEncKey.getElement());

        Document encryptedDoc = encrBuilder.build(doc, secHeader);

        builder.prependToHeader(secHeader);

        String outputString =
            XMLUtils.PrettyDocumentToString(encryptedDoc);
        assertTrue(outputString.contains("wsse:Username"));
        assertFalse(outputString.contains("wsse:Password"));
        assertTrue(outputString.contains("wsse11:Salt"));
        assertTrue(outputString.contains("wsse11:Iteration"));
        assertFalse(outputString.contains("testMethod"));
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }

        try {
            verify(encryptedDoc);
            fail("Failure expected on a key identifier");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.INVALID_SECURITY);
        }

        WSSecurityEngine newEngine = new WSSecurityEngine();
        RequestData data = new RequestData();
        data.setCallbackHandler(callbackHandler);
        data.setDecCrypto(crypto);
        data.setIgnoredBSPRules(Collections.singletonList(BSPRule.R4215));
        data.setAllowUsernameTokenNoPassword(true);

        WSSConfig config = WSSConfig.getNewInstance();
        newEngine.setWssConfig(config);
        newEngine.processSecurityHeader(encryptedDoc, data);
    }


    /**
     * Verifies the soap envelope.
     *
     * @param env soap envelope
     * @throws java.lang.Exception Thrown when there is a problem in verification
     */
    private WSHandlerResult verify(Document doc) throws Exception {
        return verify(doc, true);
    }

    private WSHandlerResult verify(
        Document doc,
        boolean allowUsernameTokenDerivedKeys
    ) throws Exception {
        WSSecurityEngine secEngine = new WSSecurityEngine();

        RequestData requestData = new RequestData();
        requestData.setAllowUsernameTokenNoPassword(allowUsernameTokenDerivedKeys);
        requestData.setCallbackHandler(callbackHandler);
        requestData.setDecCrypto(crypto);
        requestData.setSigVerCrypto(crypto);

        return secEngine.processSecurityHeader(doc, requestData);
    }

}
