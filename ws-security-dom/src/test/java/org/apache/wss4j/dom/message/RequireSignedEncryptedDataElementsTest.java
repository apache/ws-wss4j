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

import java.text.MessageFormat;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.TreeMap;

import javax.security.auth.callback.CallbackHandler;

import org.apache.wss4j.dom.WSSConfig;
import org.apache.wss4j.dom.WSSecurityEngine;
import org.apache.wss4j.dom.WSSecurityEngineResult;
import org.apache.wss4j.dom.common.CustomHandler;
import org.apache.wss4j.dom.common.KeystoreCallbackHandler;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Tests for the WSHandlerConstants.REQUIRE_SIGNED_ENCRYPTED_DATA_ELEMENTS option.
 * This test verifies some wrapping techniques are properly handled when the afore
 * mentioned option is on.
 */
public class RequireSignedEncryptedDataElementsTest extends org.junit.Assert {
    private static final org.slf4j.Logger LOG = 
        org.slf4j.LoggerFactory.getLogger(RequireSignedEncryptedDataElementsTest.class);
    private static ResourceBundle resources = ResourceBundle.getBundle("messages.wss4j_errors");
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
    
    public RequireSignedEncryptedDataElementsTest() throws Exception {
        crypto = CryptoFactory.getInstance();
        WSSConfig.init();
    }

    @org.junit.Test
    public void testEncryptedKeyRefAndDuplicatedEncDataInWsseHeader() throws Exception {
        Document encryptedSignedDoc = getRequestDocument();
        RequestData reqData = getRequestData(true);
        verify(encryptedSignedDoc, reqData);
        
        encryptedSignedDoc = getRequestDocument();
        reqData = getRequestData(false);
        TestMessageTransformer.duplicateEncryptedDataInWsseHeader(encryptedSignedDoc.getDocumentElement(), false);
        verify(encryptedSignedDoc, reqData);
        
        encryptedSignedDoc = getRequestDocument();
        reqData = getRequestData(true);
        Element newEncData = TestMessageTransformer.duplicateEncryptedDataInWsseHeader(encryptedSignedDoc.getDocumentElement(), false);
        try {
            verify(encryptedSignedDoc, reqData);
            fail("WSSecurityException expected");
        } catch (WSSecurityException e) {
            checkFailure(newEncData, e);
        }
    }
    
    @org.junit.Test
    public void testEncryptedKeyRefAndDuplicatedEncDataInWsseWrapperHeader() throws Exception {
        Document encryptedSignedDoc = getRequestDocument();
        RequestData reqData = getRequestData(true);
        verify(encryptedSignedDoc, reqData);
        
        encryptedSignedDoc = getRequestDocument();
        reqData = getRequestData(false);
        TestMessageTransformer.duplicateEncryptedDataInWsseWrapperHeader(encryptedSignedDoc.getDocumentElement(), false);
        verify(encryptedSignedDoc, reqData);
        
        encryptedSignedDoc = getRequestDocument();
        reqData = getRequestData(true);
        Element newEncData = TestMessageTransformer.duplicateEncryptedDataInWsseWrapperHeader(encryptedSignedDoc.getDocumentElement(), false);
        try {
            verify(encryptedSignedDoc, reqData);
            fail("WSSecurityException expected");
        } catch (WSSecurityException e) {
            checkFailure(newEncData, e);
        }
    }
    
    @org.junit.Test
    public void testEncryptedKeyRefAndDuplicatedEncDataInExternalWrapperElement() throws Exception {
        Document encryptedSignedDoc = getRequestDocument();
        RequestData reqData = getRequestData(true);
        verify(encryptedSignedDoc, reqData);
        
        encryptedSignedDoc = getRequestDocument();
        reqData = getRequestData(false);
        TestMessageTransformer.duplicateEncryptedDataInExternalWrapperElement(encryptedSignedDoc.getDocumentElement(), false);
        verify(encryptedSignedDoc, reqData);
        
        encryptedSignedDoc = getRequestDocument();
        reqData = getRequestData(true);
        Element newEncData = TestMessageTransformer.duplicateEncryptedDataInExternalWrapperElement(encryptedSignedDoc.getDocumentElement(), false);
        try {
            verify(encryptedSignedDoc, reqData);
            fail("WSSecurityException expected");
        } catch (WSSecurityException e) {
            checkFailure(newEncData, e);
        }
    }
    
    @org.junit.Test
    public void testReferenceListAndDuplicatedEncDataInWsseHeader() throws Exception {
        Document encryptedSignedDoc = getRequestDocument();
        RequestData reqData = getRequestData(true);
        verify(encryptedSignedDoc, reqData);
        
        encryptedSignedDoc = getRequestDocument();
        reqData = getRequestData(false);
        TestMessageTransformer.duplicateEncryptedDataInWsseHeader(encryptedSignedDoc.getDocumentElement(), true);
        verify(encryptedSignedDoc, reqData);
        
        encryptedSignedDoc = getRequestDocument();
        reqData = getRequestData(true);
        Element newEncData = TestMessageTransformer.duplicateEncryptedDataInWsseHeader(encryptedSignedDoc.getDocumentElement(), true);
        try {
            verify(encryptedSignedDoc, reqData);
            fail("WSSecurityException expected");
        } catch (WSSecurityException e) {
            checkFailure(newEncData, e);
        }
    }
    
    @org.junit.Test
    public void testReferenceListAndDuplicatedEncDataInWsseWrapperHeader() throws Exception {
        Document encryptedSignedDoc = getRequestDocument();
        RequestData reqData = getRequestData(true);
        verify(encryptedSignedDoc, reqData);
        
        encryptedSignedDoc = getRequestDocument();
        reqData = getRequestData(false);
        TestMessageTransformer.duplicateEncryptedDataInWsseWrapperHeader(encryptedSignedDoc.getDocumentElement(), true);
        verify(encryptedSignedDoc, reqData);
        
        encryptedSignedDoc = getRequestDocument();
        reqData = getRequestData(true);
        Element newEncData = TestMessageTransformer.duplicateEncryptedDataInWsseWrapperHeader(encryptedSignedDoc.getDocumentElement(), true);
        try {
            verify(encryptedSignedDoc, reqData);
            fail("WSSecurityException expected");
        } catch (WSSecurityException e) {
            checkFailure(newEncData, e);
        }
    }
    
    @org.junit.Test
    public void testReferenceListAndDuplicatedEncDataInExternalWrapperElement() throws Exception {
        Document encryptedSignedDoc = getRequestDocument();
        RequestData reqData = getRequestData(true);
        verify(encryptedSignedDoc, reqData);
        
        encryptedSignedDoc = getRequestDocument();
        reqData = getRequestData(false);
        TestMessageTransformer.duplicateEncryptedDataInExternalWrapperElement(encryptedSignedDoc.getDocumentElement(), true);
        verify(encryptedSignedDoc, reqData);
        
        encryptedSignedDoc = getRequestDocument();
        reqData = getRequestData(true);
        Element newEncData = TestMessageTransformer.duplicateEncryptedDataInExternalWrapperElement(encryptedSignedDoc.getDocumentElement(), true);
        try {
            verify(encryptedSignedDoc, reqData);
            fail("WSSecurityException expected");
        } catch (WSSecurityException e) {
            checkFailure(newEncData, e);
        }
    }
    
    @org.junit.Test
    public void testAdditionalEncryptedDataWithEmbeddedEncryptedKeyInWsseHeader() throws Exception {
        Document encryptedSignedDoc = getRequestDocument();
        RequestData reqData = getRequestData(true);
        verify(encryptedSignedDoc, reqData);
        
        encryptedSignedDoc = getRequestDocument();
        reqData = getRequestData(true);
        Element newEncData = TestMessageTransformer.addEncryptedDataWithEmbeddedEncryptedKeyInWsseHeader(encryptedSignedDoc.getDocumentElement());
        try {
            verify(encryptedSignedDoc, reqData);
            fail("WSSecurityException expected");
        } catch (WSSecurityException e) {
            checkFailure(newEncData, e);
        }
    }
    
    @org.junit.Test
    public void testEncryptedKeyRefAndDuplicatedEncDataInWsseWrapperBody() throws Exception {
        Document encryptedSignedDoc = getRequestDocumentEncryptionFirst();
        RequestData reqData = getRequestData(false);
        TestMessageTransformer.duplicateEncryptedDataInWrapperBody(encryptedSignedDoc.getDocumentElement());
        try {
            verify(encryptedSignedDoc, reqData);
            fail("WSSecurityException expected");
        } catch (WSSecurityException e) {
            assertTrue(e.getMessage().contains("The signature or decryption was invalid"));
        }
        
        encryptedSignedDoc = getRequestDocumentEncryptionFirst();
        TestMessageTransformer.duplicateEncryptedDataInWrapperBody(encryptedSignedDoc.getDocumentElement());
        reqData = getRequestData(true);
        
        try {
            verify(encryptedSignedDoc, reqData);
            fail("WSSecurityException expected");
        } catch (WSSecurityException e) {
            assertTrue(e.getMessage().contains("is not included in the signature"));
        }
    }
    
    @org.junit.Test
    public void testEncryptedKeyRefAndDuplicatedEncDataAfterWsseWrapperBody() throws Exception {
        Document encryptedSignedDoc = getRequestDocumentEncryptionFirst();
        TestMessageTransformer.duplicateEncryptedDataAfterWrapperBody(encryptedSignedDoc.getDocumentElement());
        
        RequestData reqData = getRequestData(true);
        try {
            verify(encryptedSignedDoc, reqData);
            fail("WSSecurityException expected");
        } catch (WSSecurityException e) {
            assertTrue(e.getMessage().contains("is not included in the signature"));
        }
    }
    
    private static void checkFailure(Element attackElement, WSSecurityException e) {
        final String mex = MessageFormat.format(resources.getString("requiredElementNotSigned"), attackElement);
        assertTrue(e.getMessage().contains(mex));
        assertEquals(WSSecurityException.ErrorCode.FAILED_CHECK, e.getErrorCode());
    }
    
    private RequestData getRequestData(boolean reqSignedEncData) throws WSSecurityException {
        RequestData reqData = new RequestData();
        Map<String, Object> messageContext = new TreeMap<>();
        messageContext = new java.util.TreeMap<String, Object>();
        messageContext.put(WSHandlerConstants.REQUIRE_SIGNED_ENCRYPTED_DATA_ELEMENTS, Boolean.toString(reqSignedEncData));
        reqData.setMsgContext(messageContext);
        CustomHandler handler = new CustomHandler();
        handler.receive(WSSecurityUtil.decodeAction("Encrypt Signature"), reqData);
        reqData.setCallbackHandler(callbackHandler);
        reqData.setSigVerCrypto(crypto);
        reqData.setDecCrypto(crypto);
        return reqData;
    }
    
    private Document getRequestDocument() throws Exception {
        WSSecEncrypt encrypt = new WSSecEncrypt();
        WSSecSignature sign = new WSSecSignature();
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e");
        sign.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        LOG.info("Before Encryption....");
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

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
        return encryptedSignedDoc;
    }
    
    private Document getRequestDocumentEncryptionFirst() throws Exception {
        WSSecEncrypt encrypt = new WSSecEncrypt();
        WSSecSignature sign = new WSSecSignature();
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e");
        sign.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        LOG.info("Before Encryption....");
        Document doc = SOAPUtil.toSOAPPart(SOAPMSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        Document signedDoc = sign.build(doc, crypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        Document encryptedDoc = encrypt.build(signedDoc, crypto, secHeader);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("After Encryption....");
            String outputString = 
                XMLUtils.PrettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }
        
        return encryptedDoc;
    }

    
    private List<WSSecurityEngineResult> verify(Document doc, RequestData reqData) throws Exception {
        Element elem = WSSecurityUtil.getSecurityHeader(doc, null);
        List<WSSecurityEngineResult> resultList = 
            secEngine.processSecurityHeader(elem, reqData);
        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        
        return resultList;
    }

}
