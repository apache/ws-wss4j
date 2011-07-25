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

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.common.EncodedPasswordCallbackHandler;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.common.UsernamePasswordCallbackHandler;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.message.token.UsernameToken;
import org.apache.ws.security.util.Base64;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;

import javax.security.auth.callback.CallbackHandler;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;

/**
 * WS-Security Test Case for UsernameToken Key Derivation, as defined in the 
 * UsernameTokenProfile 1.1 specification. The derived keys are used to encrypt
 * and sign, as per wsc:DerivedKeyToken.
 */
public class UTDerivedKeyTest extends org.junit.Assert {
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(UTDerivedKeyTest.class);
    private CallbackHandler callbackHandler = new UsernamePasswordCallbackHandler();
    private Crypto crypto = null;
    
    public UTDerivedKeyTest() throws Exception {
        crypto = CryptoFactory.getInstance();
    }

    /**
     * Unit test for the UsernameToken derived key functionality 
     */
    @org.junit.Test
    public void testUsernameTokenUnit() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
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
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
        assertTrue(outputString.indexOf("wsse:Username") != -1);
        assertTrue(outputString.indexOf("wsse:Password") == -1);
        assertTrue(outputString.indexOf("wsse11:Salt") != -1);
        assertTrue(outputString.indexOf("wsse11:Iteration") != -1);
        
        byte[] derivedKey = UsernameToken.generateDerivedKey("security", salt, 500);
        assertTrue(derivedKey.length == 20);
        
        // "c2VjdXJpdHk=" is the Base64 encoding of "security"
        derivedKey = UsernameToken.generateDerivedKey(Base64.decode("c2VjdXJpdHk="), salt, 500);
        assertTrue(derivedKey.length == 20);
    }

    /**
     * Test for encoded passwords.
     */
    @org.junit.Test
    public void testDerivedKeyWithEncodedPasswordBaseline() throws Exception {
        String password = "password";
        // The SHA-1 of the password is known as a password equivalent in the UsernameToken specification.
        byte[] passwordHash = MessageDigest.getInstance("SHA-1").digest(password.getBytes("UTF-8"));

        byte[] salt = Base64.decode("LKpycbfgRzwDnBz6kkhAAQ==");
        int iteration = 1049;
        byte[] expectedDerivedKey = Base64.decode("C7Ll/OY4TECb6hZuMMiX/5hzszo=");
        byte[] derivedKey = UsernameToken.generateDerivedKey(passwordHash, salt, iteration);
        assertTrue("the derived key is not as expected", Arrays.equals(expectedDerivedKey, derivedKey));
    }

    /**
     * Test using a UsernameToken derived key for encrypting a SOAP body
     */
    @org.junit.Test
    public void testDerivedKeyEncryption() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
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
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(encryptedDoc);
        assertTrue(outputString.indexOf("wsse:Username") != -1);
        assertTrue(outputString.indexOf("wsse:Password") == -1);
        assertTrue(outputString.indexOf("wsse11:Salt") != -1);
        assertTrue(outputString.indexOf("wsse11:Iteration") != -1);
        assertTrue(outputString.indexOf("testMethod") == -1);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        
        verify(encryptedDoc);
    }
    
    /**
     * Test using a UsernameToken derived key for encrypting a SOAP body
     */
    @org.junit.Test
    public void testDerivedKeyEncryptionWithEncodedPassword() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setPasswordsAreEncoded(true);
        builder.setUserInfo("bob", Base64.encode(MessageDigest.getInstance("SHA-1").digest("security".getBytes("UTF-8"))));
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
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(encryptedDoc);
        assertTrue(outputString.indexOf("wsse:Username") != -1);
        assertTrue(outputString.indexOf("wsse:Password") == -1);
        assertTrue(outputString.indexOf("wsse11:Salt") != -1);
        assertTrue(outputString.indexOf("wsse11:Iteration") != -1);
        assertTrue(outputString.indexOf("testMethod") == -1);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        
        WSSecurityEngine newEngine = new WSSecurityEngine();
        newEngine.getWssConfig().setPasswordsAreEncoded(true);
        newEngine.processSecurityHeader(
            encryptedDoc, null, new EncodedPasswordCallbackHandler(), null
        );
    }
    
    /**
     * Test using a UsernameToken derived key for encrypting a SOAP body. In this test the
     * derived key is modified before encryption, and so decryption should fail.
     */
    @org.junit.Test
    public void testDerivedKeyChangedEncryption() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
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
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(encryptedDoc);
        assertTrue(outputString.indexOf("wsse:Username") != -1);
        assertTrue(outputString.indexOf("wsse:Password") == -1);
        assertTrue(outputString.indexOf("wsse11:Salt") != -1);
        assertTrue(outputString.indexOf("wsse11:Iteration") != -1);
        assertTrue(outputString.indexOf("testMethod") == -1);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        
        try {
            verify(encryptedDoc);
            fail("Failure expected on a bad derived encryption");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.FAILED_CHECK);
            // expected
        }
    }
    
    /**
     * Test using a UsernameToken derived key for encrypting a SOAP body. In this test the
     * user is "colm" rather than "bob", and so decryption should fail.
     */
    @org.junit.Test
    public void testDerivedKeyBadUserEncryption() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
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
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(encryptedDoc);
        assertTrue(outputString.indexOf("wsse:Username") != -1);
        assertTrue(outputString.indexOf("wsse:Password") == -1);
        assertTrue(outputString.indexOf("wsse11:Salt") != -1);
        assertTrue(outputString.indexOf("wsse11:Iteration") != -1);
        assertTrue(outputString.indexOf("testMethod") == -1);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        
        try {
            verify(encryptedDoc);
            fail("Failure expected on a bad derived encryption");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.FAILED_AUTHENTICATION);
            // expected
        }
    }
    
    /**
     * Test using a UsernameToken derived key for signing a SOAP body
     */
    @org.junit.Test
    public void testDerivedKeySignature() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
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
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
        assertTrue(outputString.indexOf("wsse:Username") != -1);
        assertTrue(outputString.indexOf("wsse:Password") == -1);
        assertTrue(outputString.indexOf("wsse11:Salt") != -1);
        assertTrue(outputString.indexOf("wsse11:Iteration") != -1);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(signedDoc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN);
        java.security.Principal principal = 
            (java.security.Principal) actionResult.get(WSSecurityEngineResult.TAG_PRINCIPAL);
        // System.out.println(principal.getName());
        assertTrue(principal.getName().indexOf("DK") != -1);
    }
    
    /**
     * Test using a UsernameToken derived key for signing a SOAP body
     */
    @org.junit.Test
    public void testDerivedKeySignatureWithEncodedPassword() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setPasswordsAreEncoded(true);
        builder.setUserInfo("bob", Base64.encode(MessageDigest.getInstance("SHA-1").digest("security".getBytes("UTF-8"))));
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
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
        assertTrue(outputString.indexOf("wsse:Username") != -1);
        assertTrue(outputString.indexOf("wsse:Password") == -1);
        assertTrue(outputString.indexOf("wsse11:Salt") != -1);
        assertTrue(outputString.indexOf("wsse11:Iteration") != -1);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        
        WSSecurityEngine newEngine = new WSSecurityEngine();
        newEngine.getWssConfig().setPasswordsAreEncoded(true);
        List<WSSecurityEngineResult> results =  newEngine.processSecurityHeader(
            signedDoc, null, new EncodedPasswordCallbackHandler(), null
        );
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.SIGN);
        java.security.Principal principal = 
            (java.security.Principal) actionResult.get(WSSecurityEngineResult.TAG_PRINCIPAL);
        // System.out.println(principal.getName());
        assertTrue(principal.getName().indexOf("DK") != -1);
    }
    
    /**
     * Test using a UsernameToken derived key for signing a SOAP body. In this test the
     * derived key is modified before signature, and so signature verification should
     * fail.
     */
    @org.junit.Test
    public void testDerivedKeyChangedSignature() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        WSSecUsernameToken builder = new WSSecUsernameToken();
        builder.setUserInfo("bob", "security");
        builder.addDerivedKey(true, null, 1000);
        builder.prepare(doc);
        
        byte[] derivedKey = builder.getDerivedKey();
        derivedKey[5] = 12;
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
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }

        try {
            verify(signedDoc);
            fail("Failure expected on a bad derived signature");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.FAILED_CHECK);
            // expected
        }
    }
    
    /**
     * Test using a UsernameToken derived key for signing a SOAP body. In this test the
     * user is "colm" rather than "bob", and so signature verification should fail.
     */
    @org.junit.Test
    public void testDerivedKeyBadUserSignature() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
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
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }

        try {
            verify(signedDoc);
            fail("Failure expected on a bad derived signature");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.FAILED_AUTHENTICATION);
            // expected
        }
    }
    
    /**
     * Unit test for creating a Username Token with no salt element that is used for
     * deriving a key for encryption.
     */
    @org.junit.Test
    public void testNoSaltEncryption() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        UsernameToken usernameToken = new UsernameToken(true, doc, null);
        usernameToken.setName("bob");
        WSSConfig config = WSSConfig.getNewInstance();
        usernameToken.setID(config.getIdAllocator().createId("UsernameToken-", usernameToken));
        
        byte[] salt = UsernameToken.generateSalt(false);
        usernameToken.addIteration(doc, 1000);
        
        byte[] derivedKey = UsernameToken.generateDerivedKey("security", salt, 1000);
        
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
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
        assertTrue(outputString.indexOf("wsse:Username") != -1);
        assertTrue(outputString.indexOf("wsse:Password") == -1);
        assertTrue(outputString.indexOf("wsse11:Salt") == -1);
        assertTrue(outputString.indexOf("wsse11:Iteration") != -1);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        
        try {
            verify(encryptedDoc);
            fail("Failure expected on no salt element");
        } catch (WSSecurityException ex) {
            // expected
        }
    }
    
    /**
     * Unit test for creating a Username Token with no iteration element that is used for
     * deriving a key for encryption.
     */
    @org.junit.Test
    public void testNoIterationEncryption() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        UsernameToken usernameToken = new UsernameToken(true, doc, null);
        usernameToken.setName("bob");
        WSSConfig config = WSSConfig.getNewInstance();
        usernameToken.setID(config.getIdAllocator().createId("UsernameToken-", usernameToken));
        
        byte[] salt = usernameToken.addSalt(doc, null, false);
        byte[] derivedKey = UsernameToken.generateDerivedKey("security", salt, 1000);
        
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
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
        assertTrue(outputString.indexOf("wsse:Username") != -1);
        assertTrue(outputString.indexOf("wsse:Password") == -1);
        assertTrue(outputString.indexOf("wsse11:Salt") != -1);
        assertTrue(outputString.indexOf("wsse11:Iteration") == -1);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        
        try {
            verify(encryptedDoc);
            fail("Failure expected on no iteration element");
        } catch (WSSecurityException ex) {
            // expected
        }
    }
    
    /**
     * Unit test for creating a Username Token with an iteration value < 1000 that is used for
     * deriving a key for encryption.
     */
    @org.junit.Test
    public void testLowIterationEncryption() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        UsernameToken usernameToken = new UsernameToken(true, doc, null);
        usernameToken.setName("bob");
        WSSConfig config = WSSConfig.getNewInstance();
        usernameToken.setID(config.getIdAllocator().createId("UsernameToken-", usernameToken));
        
        usernameToken.addIteration(doc, 500);
        byte[] salt = usernameToken.addSalt(doc, null, false);
        byte[] derivedKey = UsernameToken.generateDerivedKey("security", salt, 500);
        
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
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
        assertTrue(outputString.indexOf("wsse:Username") != -1);
        assertTrue(outputString.indexOf("wsse:Password") == -1);
        assertTrue(outputString.indexOf("wsse11:Salt") != -1);
        assertTrue(outputString.indexOf("wsse11:Iteration") != -1);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        
        try {
            verify(encryptedDoc);
            fail("Failure expected on a low iteration value");
        } catch (WSSecurityException ex) {
            // expected
        }
        
        // Turn off BSP compliance and it should work
        config.setWsiBSPCompliant(false);
        WSSecurityEngine newEngine = new WSSecurityEngine();
        newEngine.setWssConfig(config);
        newEngine.processSecurityHeader(doc, null, callbackHandler, crypto);
    }

    
    /**
     * Test using a UsernameToken derived key for encrypting a SOAP body. The Reference to the
     * UsernameToken contains a non-standard value type, which is rejected when BSP compliance
     * is turned on.
     */
    @org.junit.Test
    public void testBadValueType() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
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
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(encryptedDoc);
        assertTrue(outputString.indexOf("wsse:Username") != -1);
        assertTrue(outputString.indexOf("wsse:Password") == -1);
        assertTrue(outputString.indexOf("wsse11:Salt") != -1);
        assertTrue(outputString.indexOf("wsse11:Iteration") != -1);
        assertTrue(outputString.indexOf("testMethod") == -1);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        
        try {
            verify(encryptedDoc);
            fail("Failure expected on a bad value type");
        } catch (WSSecurityException ex) {
            // expected
        }
        
        // Turn off BSP compliance and it should work
        WSSConfig config = WSSConfig.getNewInstance();
        config.setWsiBSPCompliant(false);
        WSSecurityEngine newEngine = new WSSecurityEngine();
        newEngine.setWssConfig(config);
        newEngine.processSecurityHeader(doc, null, callbackHandler, crypto);
    }

    
    /**
     * Test using a UsernameToken derived key for encrypting a SOAP body. A KeyIdentifier is
     * used to refer to the UsernameToken, which is forbidden by the BSP.
     */
    @org.junit.Test
    public void testKeyIdentifier() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
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
            org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(encryptedDoc);
        assertTrue(outputString.indexOf("wsse:Username") != -1);
        assertTrue(outputString.indexOf("wsse:Password") == -1);
        assertTrue(outputString.indexOf("wsse11:Salt") != -1);
        assertTrue(outputString.indexOf("wsse11:Iteration") != -1);
        assertTrue(outputString.indexOf("testMethod") == -1);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        
        try {
            verify(encryptedDoc);
            fail("Failure expected on a key identifier");
        } catch (WSSecurityException ex) {
            // expected
        }
        
        // Turn off BSP compliance and it should work
        WSSConfig config = WSSConfig.getNewInstance();
        config.setWsiBSPCompliant(false);
        WSSecurityEngine newEngine = new WSSecurityEngine();
        newEngine.setWssConfig(config);
        newEngine.processSecurityHeader(doc, null, callbackHandler, crypto);
    }

    
    /**
     * Verifies the soap envelope.
     * 
     * @param env soap envelope
     * @throws java.lang.Exception Thrown when there is a problem in verification
     */
    private List<WSSecurityEngineResult> verify(Document doc) throws Exception {
        WSSecurityEngine secEngine = new WSSecurityEngine();
        return secEngine.processSecurityHeader(doc, null, callbackHandler, crypto);
    }

}
