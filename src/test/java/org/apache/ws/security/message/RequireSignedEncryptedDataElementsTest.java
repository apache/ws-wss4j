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

import java.text.MessageFormat;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.TreeMap;

import javax.security.auth.callback.CallbackHandler;

import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.common.CustomHandler;
import org.apache.ws.security.common.KeystoreCallbackHandler;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Tests for the WSHandlerConstants.REQUIRE_SIGNED_ENCRYPTED_DATA_ELEMENTS option.
 * This test verifies some wrapping techniques are properly handled when the afore
 * mentioned option is on.
 * 
 * @author <a href="mailto:alessio.soldano@jboss.com">Alessio Soldano</a>
 */
public class RequireSignedEncryptedDataElementsTest extends org.junit.Assert {
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(RequireSignedEncryptedDataElementsTest.class);
    private static ResourceBundle resources = ResourceBundle.getBundle("org.apache.ws.security.errors");
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
    
    private static void checkFailure(Element attackElement, WSSecurityException e) {
        final String mex = MessageFormat.format(resources.getString("requiredElementNotSigned"), attackElement);
        assertTrue(e.getMessage().contains(mex));
        assertEquals(WSSecurityException.FAILED_CHECK, e.getErrorCode());
    }
    
    private RequestData getRequestData(boolean reqSignedEncData) throws WSSecurityException {
        RequestData reqData = new RequestData();
        Map<String, Object> messageContext = new TreeMap<String, Object>();
        messageContext = new java.util.TreeMap<String, Object>();
        messageContext.put(WSHandlerConstants.REQUIRE_SIGNED_ENCRYPTED_DATA_ELEMENTS, Boolean.toString(reqSignedEncData));
        reqData.setMsgContext(messageContext);
        CustomHandler handler = new CustomHandler();
        handler.receive(WSSecurityUtil.decodeAction("Encrypt Signature", new LinkedList<Integer>()), reqData);
        reqData.setCallbackHandler(callbackHandler);
        reqData.setSigCrypto(crypto);
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
        return encryptedSignedDoc;
    }

    
    private List<WSSecurityEngineResult> verify(Document doc, RequestData reqData) throws Exception {
        Element elem = WSSecurityUtil.getSecurityHeader(doc, null);
        List<WSSecurityEngineResult> resultList = 
            secEngine.processSecurityHeader(elem, reqData);
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        
        return resultList;
    }

}
