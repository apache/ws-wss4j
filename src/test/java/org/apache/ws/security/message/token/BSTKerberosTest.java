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

package org.apache.ws.security.message.token;

import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.common.KeystoreCallbackHandler;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.message.WSSecEncrypt;
import org.apache.ws.security.message.WSSecSignature;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.WSSecTimestamp;
import org.apache.ws.security.util.Base64;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.ws.security.validate.Credential;
import org.apache.ws.security.validate.Validator;
import org.w3c.dom.Document;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.callback.CallbackHandler;
import javax.xml.crypto.dsig.SignatureMethod;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * This is a test for the Kerberos Token Profile 1.1
 */
public class BSTKerberosTest extends org.junit.Assert {
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(BSTKerberosTest.class);
    private static final String AP_REQ = WSConstants.WSS_GSS_KRB_V5_AP_REQ;
    private static final String BASE64_NS = 
        WSConstants.SOAPMESSAGE_NS + "#Base64Binary";
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private CallbackHandler callbackHandler = new KeystoreCallbackHandler();
    private Crypto crypto = null;
    
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

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        BinarySecurity bst = new BinarySecurity(doc);
        bst.setValueType(AP_REQ);
        bst.setEncodingType(BASE64_NS);
        bst.setToken("12345678".getBytes());
        WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), bst.getElement());
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
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

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        BinarySecurity bst = new BinarySecurity(doc);
        bst.setValueType(AP_REQ);
        bst.setEncodingType(BASE64_NS);
        bst.setToken("12345678".getBytes());
        bst.setID("Id-" + bst.hashCode());
        WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), bst.getElement());
        
        WSSecSignature sign = new WSSecSignature();
        sign.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        sign.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        
        java.util.List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        WSEncryptionPart encP =
            new WSEncryptionPart(bst.getID());
        parts.add(encP);
        sign.setParts(parts);
        
        Document signedDoc = sign.build(doc, crypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
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

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
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
        
        java.util.List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        parts.add(new WSEncryptionPart(bst.getID()));
        parts.add(new WSEncryptionPart(timestamp.getId()));
        sign.setParts(parts);
        
        Document signedDoc = sign.build(doc, crypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
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

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        BinarySecurity bst = new BinarySecurity(doc);
        bst.setValueType(AP_REQ);
        bst.setEncodingType(BASE64_NS);
        bst.setToken("12345678".getBytes());
        WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), bst.getElement());
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(doc);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.BST);
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

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        BinarySecurity bst = new BinarySecurity(doc);
        bst.setValueType(AP_REQ);
        bst.setEncodingType(BASE64_NS);
        bst.setToken("12345678".getBytes());
        WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), bst.getElement());
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
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

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
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
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
    }
    
    /**
     * A test for signing using a KeyIdentifier to a Kerberos token
     */
    @org.junit.Test
    public void testKerberosSignatureKICreation() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
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
        
        byte[] digestBytes = WSSecurityUtil.generateDigest(keyData);
        sign.setCustomTokenId(Base64.encode(digestBytes));
        sign.setSecretKey(keyData);
        
        Document signedDoc = sign.build(doc, crypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
    }
    
    /**
     * A test for encryption using a direct reference to a Kerberos token
     */
    @org.junit.Test
    public void testKerberosEncryptionDRCreation() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
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
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }
    }
    
    /**
     * A test for encryption using a Key Identifier to a Kerberos token
     */
    @org.junit.Test
    public void testKerberosEncryptionKICreation() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
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
        
        byte[] digestBytes = WSSecurityUtil.generateDigest(keyData);
        builder.setEncKeyId(Base64.encode(digestBytes));
        
        Document encryptedDoc = builder.build(doc, crypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(encryptedDoc);
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
    private List<WSSecurityEngineResult> verify(Document doc) throws Exception {
        List<WSSecurityEngineResult> results = 
            secEngine.processSecurityHeader(doc, null, callbackHandler, crypto);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Verfied and decrypted message:");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
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
                throw new WSSecurityException(WSSecurityException.FAILURE);
            }

            if (!AP_REQ.equals(token.getValueType())) {
                throw new WSSecurityException(WSSecurityException.FAILURE);
            }
            
            byte[] tokenBytes = token.getToken();
            if (!Arrays.equals(tokenBytes, "12345678".getBytes())) {
                throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
            }
            return credential;
        }
        
    }
    
}
