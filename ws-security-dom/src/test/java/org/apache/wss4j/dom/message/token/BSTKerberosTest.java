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

package org.apache.wss4j.dom.message.token;

import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.common.KeystoreCallbackHandler;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.token.BinarySecurity;
import org.apache.wss4j.common.util.KeyUtils;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.dom.message.WSSecEncrypt;
import org.apache.wss4j.dom.message.WSSecSignature;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecTimestamp;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.apache.wss4j.dom.validate.Credential;
import org.apache.wss4j.dom.validate.Validator;
import org.apache.xml.security.utils.Base64;
import org.w3c.dom.Document;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.callback.CallbackHandler;
import javax.xml.crypto.dsig.SignatureMethod;

import java.util.Arrays;

/**
 * This is a test for the Kerberos Token Profile 1.1
 */
public class BSTKerberosTest extends org.junit.Assert {
    private static final org.slf4j.Logger LOG = 
        org.slf4j.LoggerFactory.getLogger(BSTKerberosTest.class);
    private static final String AP_REQ = WSConstants.WSS_GSS_KRB_V5_AP_REQ;
    private static final String BASE64_NS = 
        WSConstants.SOAPMESSAGE_NS + "#Base64Binary";
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private CallbackHandler callbackHandler = new KeystoreCallbackHandler();
    private Crypto crypto = null;
    
    @org.junit.AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }
    
    public BSTKerberosTest() throws Exception {
        WSSConfig.init();
        crypto = CryptoFactory.getInstance();
    }

    /**
     * A unit test for creating BinarySecurityTokens
     */
    @org.junit.Test
    public void testCreateBinarySecurityToken() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        
        BinarySecurity bst = new BinarySecurity(doc);
        bst.setValueType(AP_REQ);
        bst.setEncodingType(BASE64_NS);
        bst.setToken("12345678".getBytes());
        WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), bst.getElement());
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        
        assertTrue(AP_REQ.equals(bst.getValueType()));
        assertTrue(BASE64_NS.equals(bst.getEncodingType()));
        assertTrue(bst.getToken() != null);
    }
    
    
    /**
     * A test for signing a Kerberos BST
     */
    @org.junit.Test
    public void testSignBST() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        
        BinarySecurity bst = new BinarySecurity(doc);
        bst.setValueType(AP_REQ);
        bst.setEncodingType(BASE64_NS);
        bst.setToken("12345678".getBytes());
        bst.setID("Id-" + bst.hashCode());
        WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), bst.getElement());
        
        WSSecSignature sign = new WSSecSignature();
        sign.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        sign.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        
        WSEncryptionPart encP =
            new WSEncryptionPart(bst.getID());
        sign.getParts().add(encP);
        
        Document signedDoc = sign.build(doc, crypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        verify(signedDoc);
    }
    
    /**
     * A test for signing a Kerberos BST as well as a Timestamp
     */
    @org.junit.Test
    public void testSignBSTTimestamp() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        
        BinarySecurity bst = new BinarySecurity(doc);
        bst.setValueType(AP_REQ);
        bst.setEncodingType(BASE64_NS);
        bst.setToken("12345678".getBytes());
        bst.setID("Id-" + bst.hashCode());
        WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), bst.getElement());
        
        WSSecTimestamp timestamp = new WSSecTimestamp();
        timestamp.setTimeToLive(600);
        timestamp.build(doc, secHeader);
        
        WSSecSignature sign = new WSSecSignature();
        sign.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        sign.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        
        sign.getParts().add(new WSEncryptionPart(bst.getID()));
        sign.getParts().add(new WSEncryptionPart(timestamp.getId()));
        
        Document signedDoc = sign.build(doc, crypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        verify(signedDoc);
    }
    
    /**
     * Test Validating a Kerberos BinarySecurityToken
     */
    @org.junit.Test
    public void testProcessToken() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        
        BinarySecurity bst = new BinarySecurity(doc);
        bst.setValueType(AP_REQ);
        bst.setEncodingType(BASE64_NS);
        bst.setToken("12345678".getBytes());
        WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), bst.getElement());
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        
        WSHandlerResult results = verify(doc);
        WSSecurityEngineResult actionResult = 
            results.getActionResults().get(WSConstants.BST).get(0);
        BinarySecurity token =
            (BinarySecurity)actionResult.get(WSSecurityEngineResult.TAG_BINARY_SECURITY_TOKEN);
        assertTrue(token != null);
        
        assertTrue(AP_REQ.equals(token.getValueType()));
        assertTrue(BASE64_NS.equals(token.getEncodingType()));
        assertTrue(token.getToken() != null);
    }
    
    /**
     * Test Validating a Kerberos BinarySecurityToken using a custom Validator instance.
     */
    @org.junit.Test
    public void testProcessTokenCustomValidator() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        
        BinarySecurity bst = new BinarySecurity(doc);
        bst.setValueType(AP_REQ);
        bst.setEncodingType(BASE64_NS);
        bst.setToken("12345678".getBytes());
        WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), bst.getElement());
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        
        WSSecurityEngine customEngine = new WSSecurityEngine();
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        wssConfig.setValidator(WSSecurityEngine.BINARY_TOKEN, new KerberosValidator());
        customEngine.setWssConfig(wssConfig);
        customEngine.processSecurityHeader(doc, null, callbackHandler, crypto);
        
        bst.setToken("12345679".getBytes());
        try {
            customEngine.processSecurityHeader(doc, null, callbackHandler, crypto);
            fail("Failure expected on a bad token");
        } catch (WSSecurityException ex) {
            // expected
        }
    }
    
    /**
     * A test for signing using a direct reference to a Kerberos token
     */
    @org.junit.Test
    public void testKerberosSignatureDRCreation() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        
        BinarySecurity bst = new BinarySecurity(doc);
        bst.setValueType(AP_REQ);
        bst.setEncodingType(BASE64_NS);
        
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey key = keyGen.generateKey();
        byte[] keyData = key.getEncoded();
        
        bst.setToken(keyData);
        bst.setID("Id-" + bst.hashCode());
        WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), bst.getElement());
        
        WSSecSignature sign = new WSSecSignature();
        sign.setSignatureAlgorithm(SignatureMethod.HMAC_SHA1);
        sign.setKeyIdentifierType(WSConstants.CUSTOM_SYMM_SIGNING);
        sign.setCustomTokenValueType(AP_REQ);
        sign.setCustomTokenId(bst.getID());
        sign.setSecretKey(keyData);
        
        Document signedDoc = sign.build(doc, crypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
    }
    
    /**
     * A test for signing using a KeyIdentifier to a Kerberos token
     */
    @org.junit.Test
    public void testKerberosSignatureKICreation() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        
        BinarySecurity bst = new BinarySecurity(doc);
        bst.setValueType(AP_REQ);
        bst.setEncodingType(BASE64_NS);
        
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey key = keyGen.generateKey();
        byte[] keyData = key.getEncoded();
        
        bst.setToken(keyData);
        bst.setID("Id-" + bst.hashCode());
        WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), bst.getElement());
        
        WSSecSignature sign = new WSSecSignature();
        sign.setSignatureAlgorithm(SignatureMethod.HMAC_SHA1);
        sign.setKeyIdentifierType(WSConstants.CUSTOM_KEY_IDENTIFIER);
        sign.setCustomTokenValueType(WSConstants.WSS_KRB_KI_VALUE_TYPE);
        
        byte[] digestBytes = KeyUtils.generateDigest(keyData);
        sign.setCustomTokenId(Base64.encode(digestBytes));
        sign.setSecretKey(keyData);
        
        Document signedDoc = sign.build(doc, crypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
    }
    
    /**
     * A test for encryption using a direct reference to a Kerberos token
     */
    @org.junit.Test
    public void testKerberosEncryptionDRCreation() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        
        BinarySecurity bst = new BinarySecurity(doc);
        bst.setValueType(AP_REQ);
        bst.setEncodingType(BASE64_NS);
        
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey key = keyGen.generateKey();
        byte[] keyData = key.getEncoded();
        
        bst.setToken(keyData);
        bst.setID("Id-" + bst.hashCode());
        WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), bst.getElement());
        
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setSymmetricEncAlgorithm(WSConstants.AES_128);
        builder.setSymmetricKey(key);
        builder.setEncryptSymmKey(false);
        builder.setCustomReferenceValue(AP_REQ);
        builder.setEncKeyId(bst.getID());
        Document encryptedDoc = builder.build(doc, crypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }
    }
    
    /**
     * A test for encryption using a Key Identifier to a Kerberos token
     */
    @org.junit.Test
    public void testKerberosEncryptionKICreation() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        
        BinarySecurity bst = new BinarySecurity(doc);
        bst.setValueType(AP_REQ);
        bst.setEncodingType(BASE64_NS);
        
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey key = keyGen.generateKey();
        byte[] keyData = key.getEncoded();
        
        bst.setToken(keyData);
        bst.setID("Id-" + bst.hashCode());
        WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), bst.getElement());
        
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setSymmetricEncAlgorithm(WSConstants.AES_128);
        builder.setSymmetricKey(key);
        builder.setEncryptSymmKey(false);
        builder.setCustomReferenceValue(WSConstants.WSS_KRB_KI_VALUE_TYPE);
        
        byte[] digestBytes = KeyUtils.generateDigest(keyData);
        builder.setEncKeyId(Base64.encode(digestBytes));
        
        Document encryptedDoc = builder.build(doc, crypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }
    }


    
    /**
     * Verifies the soap envelope
     * <p/>
     * 
     * @param doc 
     * @throws Exception Thrown when there is a problem in verification
     */
    private WSHandlerResult verify(Document doc) throws Exception {
        WSHandlerResult results = 
            secEngine.processSecurityHeader(doc, null, callbackHandler, crypto);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Verfied and decrypted message:");
            String outputString = 
                XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        return results;
    }

    
    /**
     * A dummy validator for a Kerberos BST token.
     */
    private static class KerberosValidator implements Validator {

        public Credential validate(Credential credential, RequestData data) throws WSSecurityException {
            BinarySecurity token = credential.getBinarySecurityToken();
            if (token == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE);
            }

            if (!AP_REQ.equals(token.getValueType())) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE);
            }
            
            byte[] tokenBytes = token.getToken();
            if (!Arrays.equals(tokenBytes, "12345678".getBytes())) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
            }
            return credential;
        }
        
    }
    
}
