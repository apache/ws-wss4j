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
import org.apache.wss4j.dom.WSDataRef;
import org.apache.wss4j.dom.WSSConfig;
import org.apache.wss4j.dom.WSSecurityEngine;
import org.apache.wss4j.dom.WSSecurityEngineResult;
import org.apache.wss4j.dom.common.CustomHandler;
import org.apache.wss4j.dom.common.KeystoreCallbackHandler;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.dom.handler.HandlerAction;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.util.XMLUtils;
import org.w3c.dom.Document;

import javax.security.auth.callback.CallbackHandler;
import javax.xml.crypto.dsig.SignatureMethod;

import java.util.List;
import java.util.ArrayList;

/**
 * A set of tests for combined signature/encryption, verification/decryption.
 */
public class SignatureEncryptionTest extends org.junit.Assert {
    private static final org.slf4j.Logger LOG = 
        org.slf4j.LoggerFactory.getLogger(SignatureEncryptionTest.class);
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
    
    private Crypto crypto = null;
    
    @org.junit.AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }
    
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

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        Document encryptedDoc = encrypt.build(doc, crypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("After Encryption....");
            String outputString = 
                XMLUtils.PrettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }
        
        Document encryptedSignedDoc = sign.build(encryptedDoc, crypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString = 
                XMLUtils.PrettyDocumentToString(encryptedSignedDoc);
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

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSEncryptionPart part = 
            new WSEncryptionPart(
                    "add",
                    "http://ws.apache.org/counter/counter_port_type",
                    "Element");
        encrypt.getParts().add(part);
        
        Document encryptedDoc = encrypt.build(doc, crypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("After Encryption....");
            String outputString = 
                XMLUtils.PrettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }
        
        WSEncryptionPart signPart = 
            new WSEncryptionPart(
                    WSConstants.ENC_DATA_LN,
                    WSConstants.ENC_NS,
                    "Element");
        sign.getParts().add(signPart);
        
        Document encryptedSignedDoc = sign.build(encryptedDoc, crypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString = 
                XMLUtils.PrettyDocumentToString(encryptedSignedDoc);
            LOG.debug(outputString);
        }
        
        WSHandlerResult results = verify(encryptedSignedDoc);
        
        List<WSSecurityEngineResult> sigSecEngResults = 
            results.getActionResults().get(WSConstants.SIGN);
        
        List<WSSecurityEngineResult> encSecEngResults = 
            results.getActionResults().get(WSConstants.ENCR);
        
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
        
        assertNull(sigDataRefs.get(0)
                .getProtectedElement().getAttributeNodeNS(WSConstants.WSU_NS, "Id"));
        
        assertTrue(sigDataRefs.get(0).getWsuId().contains(
                encDataRefs.get(0).getWsuId()));
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

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

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
        
        WSEncryptionPart encP =
            new WSEncryptionPart(
                "add",
                "http://ws.apache.org/counter/counter_port_type",
                "");
        encrypt.getParts().add(encP);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        Document signedDoc = sign.build(doc, crypto, secHeader);
        Document encryptedSignedDoc = encrypt.build(signedDoc, crypto, secHeader);
        LOG.info("WSS198");
        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(encryptedSignedDoc);
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

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        
        Document signedDoc = sign.build(doc, crypto, secHeader);
        Document encryptedSignedDoc = encrypt.build(signedDoc, crypto, secHeader);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed and encrypted message with IssuerSerial key identifier (both), 3DES:");
            String outputString = 
                XMLUtils.PrettyDocumentToString(encryptedSignedDoc);
            LOG.debug(outputString);
        }
        
        LOG.info("After Sign/Encryption....");
        verify(encryptedSignedDoc);
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

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

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
                XMLUtils.PrettyDocumentToString(encryptedSignedDoc);
            LOG.debug(outputString);
        }

        LOG.info("After Sign/Encryption....");
        verify(encryptedSignedDoc);
    }

    @org.junit.Test
    public void testEncryptionSigningHandler() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        java.util.Map<String, Object> messageContext = new java.util.TreeMap<String, Object>();
        messageContext.put(WSHandlerConstants.PW_CALLBACK_REF, new KeystoreCallbackHandler());
        messageContext.put(WSHandlerConstants.ENC_PROP_REF_ID, "" + crypto.hashCode());
        messageContext.put(WSHandlerConstants.SIG_PROP_REF_ID, "" + crypto.hashCode());
        messageContext.put("" + crypto.hashCode(), crypto);
        reqData.setMsgContext(messageContext);
        reqData.setUsername("wss40");
        
        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        List<HandlerAction> handlerActions = new ArrayList<>();
        HandlerAction action = new HandlerAction(WSConstants.ENCR);
        handlerActions.add(action);
        action = new HandlerAction(WSConstants.SIGN);
        handlerActions.add(action);
        
        handler.send(
            doc, 
            reqData, 
            handlerActions,
            true
        );
        
        String outputString = 
            XMLUtils.PrettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        
        List<Integer> receivingActions = new ArrayList<>();
        receivingActions.add(WSConstants.ENCR);
        receivingActions.add(WSConstants.SIGN);
        messageContext.put(WSHandlerConstants.DEC_PROP_REF_ID, "" + crypto.hashCode());
        messageContext.put(WSHandlerConstants.SIG_VER_PROP_REF_ID, "" + crypto.hashCode());
        handler.receive(receivingActions, reqData);
        
        WSSecurityEngine newEngine = new WSSecurityEngine();
        newEngine.processSecurityHeader(doc, reqData);
    }
    
    @org.junit.Test
    public void testSigningEncryptionHandler() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        java.util.Map<String, Object> messageContext = new java.util.TreeMap<String, Object>();
        messageContext.put(WSHandlerConstants.PW_CALLBACK_REF, new KeystoreCallbackHandler());
        messageContext.put(WSHandlerConstants.ENC_PROP_REF_ID, "" + crypto.hashCode());
        messageContext.put(WSHandlerConstants.SIG_PROP_REF_ID, "" + crypto.hashCode());
        messageContext.put("" + crypto.hashCode(), crypto);
        reqData.setMsgContext(messageContext);
        reqData.setUsername("wss40");
        
        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        List<HandlerAction> handlerActions = new ArrayList<>();
        HandlerAction action = new HandlerAction(WSConstants.SIGN);
        handlerActions.add(action);
        action = new HandlerAction(WSConstants.ENCR);
        handlerActions.add(action);
        
        handler.send(
            doc, 
            reqData, 
            handlerActions,
            true
        );
        
        String outputString = 
            XMLUtils.PrettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug(outputString);
        }
        
        List<Integer> receivingActions = new ArrayList<>();
        receivingActions.add(WSConstants.SIGN);
        receivingActions.add(WSConstants.ENCR);
        messageContext.put(WSHandlerConstants.DEC_PROP_REF_ID, "" + crypto.hashCode());
        messageContext.put(WSHandlerConstants.SIG_VER_PROP_REF_ID, "" + crypto.hashCode());
        handler.receive(receivingActions, reqData);
        
        WSSecurityEngine newEngine = new WSSecurityEngine();
        newEngine.processSecurityHeader(doc, reqData);
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
    private WSHandlerResult verify(Document doc) throws Exception {
        WSHandlerResult resultList = 
            secEngine.processSecurityHeader(doc, null, callbackHandler, crypto);
        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        
        return resultList;
    }

}
