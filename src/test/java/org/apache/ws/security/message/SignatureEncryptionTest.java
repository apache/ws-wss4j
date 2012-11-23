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
import org.apache.ws.security.WSDataRef;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.common.KeystoreCallbackHandler;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.common.SecretKeyCallbackHandler;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;

import javax.security.auth.callback.CallbackHandler;
import javax.xml.crypto.dsig.SignatureMethod;

import java.util.List;
import java.util.ArrayList;

/**
 * A set of tests for combined signature/encryption, verification/decryption.
 * 
 * @author Davanum Srinivas (dims@yahoo.com)
 */
public class SignatureEncryptionTest extends org.junit.Assert {
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(SignatureEncryptionTest.class);
    private static final String SOAPMSG = 
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" 
        + "<SOAP-ENV:Envelope "
        +   "xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" "
        +   "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" "
        +   "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" 
        +   "<SOAP-ENV:Body>" 
        +       "<add xmlns=\"http://ws.apache.org/counter/counter_port_type\">" 
        +           "<value xmlns=\"http://blah.com\">15</value>" 
        +       "</add>" 
        +   "</SOAP-ENV:Body>" 
        + "</SOAP-ENV:Envelope>";

    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private CallbackHandler callbackHandler = new KeystoreCallbackHandler();
    
    private static final byte[] key = {
        (byte)0x31, (byte)0xfd,
        (byte)0xcb, (byte)0xda,
        (byte)0xfb, (byte)0xcd,
        (byte)0x6b, (byte)0xa8,
        (byte)0xe6, (byte)0x19,
        (byte)0xa7, (byte)0xbf,
        (byte)0x51, (byte)0xf7,
        (byte)0xc7, (byte)0x3e,
        (byte)0x80, (byte)0xae,
        (byte)0x98, (byte)0x51,
        (byte)0xc8, (byte)0x51,
        (byte)0x34, (byte)0x04,
    };
    private Crypto crypto = null;
    
    public SignatureEncryptionTest() throws Exception {
        crypto = CryptoFactory.getInstance("wss40.properties");
        WSSConfig.init();
    }

    /**
     * Test that encrypts and then signs a WS-Security envelope, then performs
     * verification and decryption <p/>
     * 
     * @throws Exception
     *             Thrown when there is any problem in signing, encryption,
     *             decryption, or verification
     */
    @org.junit.Test
    public void testEncryptionSigning() throws Exception {
        WSSecEncrypt encrypt = new WSSecEncrypt();
        WSSecSignature sign = new WSSecSignature();
        encrypt.setUserInfo("wss40");
        sign.setUserInfo("wss40", "security");
        LOG.info("Before Encryption....");
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        Document encryptedDoc = encrypt.build(doc, crypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("After Encryption....");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }
        
        Document encryptedSignedDoc = sign.build(encryptedDoc, crypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(encryptedSignedDoc);
            LOG.debug(outputString);
        }
        verify(encryptedSignedDoc);
    }
    
    
    /**
     * Test that encrypts and then signs a WS-Security envelope (including the 
     * encrypted element), then performs verification and decryption <p/>
     * 
     * @throws Exception
     *             Thrown when there is any problem in signing, encryption,
     *             decryption, or verification
     */
    @SuppressWarnings("unchecked")
    @org.junit.Test
    public void testEncryptionElementSigning() throws Exception {
        WSSecEncrypt encrypt = new WSSecEncrypt();
        WSSecSignature sign = new WSSecSignature();
        encrypt.setUserInfo("wss40");
        sign.setUserInfo("wss40", "security");
        LOG.info("Before Encryption....");
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        List<WSEncryptionPart> encParts = new ArrayList<WSEncryptionPart>();
        encParts.add(
                new WSEncryptionPart(
                        "add",
                        "http://ws.apache.org/counter/counter_port_type",
                        "Element"));
        encrypt.setParts(encParts);
        
        Document encryptedDoc = encrypt.build(doc, crypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("After Encryption....");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }
        
        List<WSEncryptionPart> sigParts = new ArrayList<WSEncryptionPart>();
        sigParts.add(
                new WSEncryptionPart(
                        WSConstants.ENC_DATA_LN,
                        WSConstants.ENC_NS,
                        "Element"));
        sign.setParts(sigParts);
        
        Document encryptedSignedDoc = sign.build(encryptedDoc, crypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(encryptedSignedDoc);
            LOG.debug(outputString);
        }
        
        List<WSSecurityEngineResult> results = verify(encryptedSignedDoc);
        
        List<WSSecurityEngineResult> sigSecEngResults = new ArrayList<WSSecurityEngineResult>();
        WSSecurityUtil.fetchAllActionResults(results, WSConstants.SIGN, sigSecEngResults);
        
        List<WSSecurityEngineResult> encSecEngResults = new ArrayList<WSSecurityEngineResult>();
        WSSecurityUtil.fetchAllActionResults(results, WSConstants.ENCR, encSecEngResults);
        
        assertEquals(1, sigSecEngResults.size());
        assertEquals(1, encSecEngResults.size());
        
        List<WSDataRef> sigDataRefs = 
            (List<WSDataRef>)(sigSecEngResults.get(0)).get(
                WSSecurityEngineResult.TAG_DATA_REF_URIS
            );
        
        List<WSDataRef> encDataRefs = 
            (List<WSDataRef>)(encSecEngResults.get(0)).get(
                WSSecurityEngineResult.TAG_DATA_REF_URIS
            );
        
        assertNotNull(sigDataRefs);
        assertNotNull(encDataRefs);
        assertEquals(1, sigDataRefs.size());
        assertEquals(1, encDataRefs.size());
        
        assertNull(((WSDataRef) sigDataRefs.get(0))
                .getProtectedElement().getAttributeNodeNS(WSConstants.WSU_NS, "Id"));
        
        assertTrue(((WSDataRef) sigDataRefs.get(0)).getWsuId().contains(
                ((WSDataRef) encDataRefs.get(0)).getWsuId()));
    }
    
    
    /**
     * Test that signs and then encrypts a WS-Security envelope, then performs
     * decryption and verification <p/>
     * 
     * @throws Exception
     *             Thrown when there is any problem in signing, encryption,
     *             decryption, or verification
     */
    @org.junit.Test
    public void testSigningEncryption() throws Exception {
        WSSecEncrypt encrypt = new WSSecEncrypt();
        WSSecSignature sign = new WSSecSignature();
        encrypt.setUserInfo("wss40");
        sign.setUserInfo("wss40", "security");
        LOG.info("Before Encryption....");
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        Document signedDoc = sign.build(doc, crypto, secHeader);
        Document encryptedSignedDoc = encrypt.build(signedDoc, crypto, secHeader);
        LOG.info("After Encryption....");
        verify(encryptedSignedDoc);
    }
    
    
    /**
     * Test that signs a SOAP Body, and then encrypts some data inside the SOAP Body.
     * As the encryption adds a wsu:Id to the encrypted element, this test checks that
     * verification still works ok.
     */
    @org.junit.Test
    public void testWSS198() throws Exception {
        WSSecEncrypt encrypt = new WSSecEncrypt();
        WSSecSignature sign = new WSSecSignature();
        encrypt.setUserInfo("wss40");
        sign.setUserInfo("wss40", "security");
        LOG.info("Before Encryption....");
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        
        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        WSEncryptionPart encP =
            new WSEncryptionPart(
                "add",
                "http://ws.apache.org/counter/counter_port_type",
                "");
        parts.add(encP);
        encrypt.setParts(parts);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        Document signedDoc = sign.build(doc, crypto, secHeader);
        Document encryptedSignedDoc = encrypt.build(signedDoc, crypto, secHeader);
        LOG.info("WSS198");
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(encryptedSignedDoc);
            LOG.debug(outputString);
        }
        verify(encryptedSignedDoc);
    }
    
    /**
     * Test that first signs, then encrypts a WS-Security envelope.
     * The test uses the IssuerSerial key identifier to get the keys for
     * signature and encryption. Encryption uses 3DES.
     * <p/>
     * 
     * @throws Exception Thrown when there is any problem in signing, encryption,
     *                   decryption, or verification
     */
    @org.junit.Test
    public void testSigningEncryptionIS3DES() throws Exception {
        WSSecEncrypt encrypt = new WSSecEncrypt();
        encrypt.setUserInfo("wss40");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        encrypt.setSymmetricEncAlgorithm(WSConstants.TRIPLE_DES);

        WSSecSignature sign = new WSSecSignature();
        sign.setUserInfo("wss40", "security");
        sign.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        LOG.info("Before Sign/Encryption....");
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        Document signedDoc = sign.build(doc, crypto, secHeader);
        Document encryptedSignedDoc = encrypt.build(signedDoc, crypto, secHeader);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed and encrypted message with IssuerSerial key identifier (both), 3DES:");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(encryptedSignedDoc);
            LOG.debug(outputString);
        }
        
        LOG.info("After Sign/Encryption....");
        verify(encryptedSignedDoc);
    }
    
    /**
     * Test that encrypts and signs a WS-Security envelope, then performs
     * verification and decryption.
     * <p/>
     * 
     * @throws Exception Thrown when there is any problem in signing, encryption,
     *                   decryption, or verification
     */
    @org.junit.Test
    public void testSigningEncryptionEmbedded() throws Exception {
        WSSecEncrypt encrypt = new WSSecEncrypt();
        WSSecSignature sign = new WSSecSignature();
        
        encrypt.setUserInfo("wss40");
        encrypt.setKeyIdentifierType(WSConstants.EMBEDDED_KEYNAME);
        encrypt.setSymmetricEncAlgorithm(WSConstants.TRIPLE_DES);        
        encrypt.setKey(key);

        sign.setUserInfo("wss40", "security");
        LOG.info("Before Encryption....");
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        encrypt.setDocument(doc);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);                
        Document signedDoc = sign.build(doc, crypto, secHeader);
        Document encryptedSignedDoc = encrypt.build(signedDoc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Encrypted message, RSA-OAEP keytransport, 3DES:");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(encryptedSignedDoc);
            LOG.debug(outputString);
        }
        LOG.info("After Encryption....");
        
        SecretKeyCallbackHandler secretKeyCallbackHandler = new SecretKeyCallbackHandler();
        secretKeyCallbackHandler.setOutboundSecret(key);
        WSSecurityEngine engine = new WSSecurityEngine();
        WSSConfig config = WSSConfig.getNewInstance();
        config.setWsiBSPCompliant(false);
        engine.setWssConfig(config);
        engine.processSecurityHeader(doc, null, secretKeyCallbackHandler, crypto);
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
    }
    
    /**
     * Test signature created using an encrypted key
     * SOAP Body is signed and encrypted. In the encryption, The ReferenceList element is 
     * put into the Encrypted Key, as a child of the EncryptedKey. Signature is created 
     * using the encrypted key. 
     */
    @org.junit.Test
    public void testEncryptedKeySignature() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);
        LOG.info("Before Sign/Encryption....");

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        WSSecEncryptedKey encrKey = new WSSecEncryptedKey();
        encrKey.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        encrKey.setUserInfo("wss40", "security");
        encrKey.setSymmetricEncAlgorithm(WSConstants.AES_192);
        encrKey.prepare(doc, crypto);   

        WSSecEncrypt encrypt = new WSSecEncrypt();
        encrypt.setEncKeyId(encrKey.getId());
        encrypt.setEphemeralKey(encrKey.getEphemeralKey());
        encrypt.setSymmetricEncAlgorithm(WSConstants.TRIPLE_DES);
        encrypt.setEncryptSymmKey(false);
        encrypt.setEncryptedKeyElement(encrKey.getEncryptedKeyElement());

        WSSecSignature sign = new WSSecSignature();
        sign.setKeyIdentifierType(WSConstants.CUSTOM_SYMM_SIGNING);
        sign.setCustomTokenId(encrKey.getId());
        sign.setSecretKey(encrKey.getEphemeralKey());
        sign.setCustomTokenValueType(WSConstants.WSS_ENC_KEY_VALUE_TYPE);
        sign.setSignatureAlgorithm(SignatureMethod.HMAC_SHA1);

        Document signedDoc = sign.build(doc, crypto, secHeader);
        Document encryptedSignedDoc = encrypt.build(signedDoc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed and encrypted message with IssuerSerial key identifier (both), 3DES:");
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(encryptedSignedDoc);
            LOG.debug(outputString);
        }

        LOG.info("After Sign/Encryption....");
        verify(encryptedSignedDoc);
    }


    /**
     * Verifies the soap envelope <p/>
     * 
     * @param envelope
     *
     * @return the <code>WSSecurityEngineResult</code>s from processing
     *
     * @throws Exception
     *             Thrown when there is a problem in verification
     */
    private List<WSSecurityEngineResult> verify(Document doc) throws Exception {
        List<WSSecurityEngineResult> resultList = 
            secEngine.processSecurityHeader(doc, null, callbackHandler, crypto);
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        
        return resultList;
    }

}
