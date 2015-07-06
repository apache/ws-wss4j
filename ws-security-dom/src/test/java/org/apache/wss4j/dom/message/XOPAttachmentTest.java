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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import javax.security.auth.callback.CallbackHandler;

import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.Attachment;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSSConfig;
import org.apache.wss4j.dom.WSSecurityEngine;
import org.apache.wss4j.dom.WSSecurityEngineResult;
import org.apache.wss4j.dom.common.KeystoreCallbackHandler;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * Test for creating / processing an xop:Include inside a CipherValue Element
 */
public class XOPAttachmentTest extends org.junit.Assert {

    private static final String SOAP_BODY = 
        "<add xmlns=\"http://ws.apache.org/counter/counter_port_type\">" 
        + "<value xmlns=\"\">15</value>" 
        + "</add>";
    
    private static final String SOAP_HEADER_MSG = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
        "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" +
        "   <soapenv:Header>" + 
        "       <foo:bar1 xmlns:foo=\"urn:foo.bar\" >baz1</foo:bar1>" + 
        "       <foo:foobar xmlns:foo=\"urn:foo.bar\" >baz</foo:foobar>" + 
        "       <foo:bar2 xmlns:foo=\"urn:foo.bar\" >baz2</foo:bar2>" +
        "   </soapenv:Header>" +
        "   <soapenv:Body>" +
        "      <ns1:testMethod xmlns:ns1=\"http://axis/service/security/test6/LogTestService8\"></ns1:testMethod>" +
        "   </soapenv:Body>" +
        "</soapenv:Envelope>";
    
    private static final org.slf4j.Logger LOG =
            org.slf4j.LoggerFactory.getLogger(XOPAttachmentTest.class);

    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private Crypto crypto = null;

    public XOPAttachmentTest() throws Exception {
        WSSConfig.init();
        crypto = CryptoFactory.getInstance();
    }

    protected byte[] readInputStream(InputStream inputStream) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try {
            int read = 0;
            byte[] buf = new byte[4096];
            while ((read = inputStream.read(buf)) != -1) {
                byteArrayOutputStream.write(buf, 0, read);
            }
            return byteArrayOutputStream.toByteArray();
        } finally {
            byteArrayOutputStream.close();
        }
    }

    // Set up a test to encrypt the SOAP Body + an attachment, which is the same content as 
    // the SOAP Body. Then replace the encrypted SOAP Body with a xop:Include to the attachment,
    // and modify the request to remove the encryption stuff pointing to the attachment.
    // (NOTE: This test was before we supported creating requests with xop:Include)
    @org.junit.Test
    public void testManualEncryptedSOAPBody() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecEncrypt encrypt = new WSSecEncrypt();
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        parts.add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Content"));
        parts.add(new WSEncryptionPart("cid:Attachments", "Content"));
        encrypt.setParts(parts);

        String attachmentId = UUID.randomUUID().toString();
        final Attachment attachment = new Attachment();
        attachment.setId(attachmentId);
        attachment.setSourceStream(new ByteArrayInputStream(SOAP_BODY.getBytes("UTF-8")));

        AttachmentCallbackHandler attachmentCallbackHandler = 
            new AttachmentCallbackHandler(Collections.singletonList(attachment));
        encrypt.setAttachmentCallbackHandler(attachmentCallbackHandler);
        List<Attachment> encryptedAttachments = attachmentCallbackHandler.getResponseAttachments();

        Document encryptedDoc = encrypt.build(doc, crypto, secHeader);
        
        // Find the SOAP Body + replace with a xop:Include to the attachment!
        Element soapBody = WSSecurityUtil.findBodyElement(encryptedDoc);
        assertNotNull(soapBody);
        Element encryptedData = 
            XMLUtils.getDirectChildElement(soapBody, "EncryptedData", WSConstants.ENC_NS);
        encryptedData.removeAttributeNS(null, "Type");
        Element cipherData = 
            XMLUtils.getDirectChildElement(encryptedData, "CipherData", WSConstants.ENC_NS);
        assertNotNull(cipherData);
        Element cipherValue = 
            XMLUtils.getDirectChildElement(cipherData, "CipherValue", WSConstants.ENC_NS);
        assertNotNull(cipherValue);
        
        WSSecurityUtil.setNamespace(cipherValue, WSConstants.XOP_NS, "xop");
        
        Element cipherValueChild = encryptedDoc.createElementNS(WSConstants.XOP_NS, "Include");
        cipherValueChild.setAttributeNS(null, "href", "cid:" + encryptedAttachments.get(0).getId());
        cipherValue.replaceChild(cipherValueChild, cipherValue.getFirstChild());
        
        // Remove EncryptedData structure from the security header (which encrypted the attachment
        // in the first place)
        Element securityHeader = 
            WSSecurityUtil.findWsseSecurityHeaderBlock(encryptedDoc, encryptedDoc.getDocumentElement(), false);
        Element encryptedAttachmentData = 
            XMLUtils.getDirectChildElement(securityHeader, "EncryptedData", WSConstants.ENC_NS);
        assertNotNull(encryptedAttachmentData);
        String encryptedDataId = encryptedAttachmentData.getAttributeNS(null, "Id");
        securityHeader.removeChild(encryptedAttachmentData);

        // Now get EncryptedKey + remove the reference to the EncryptedData above
        Element encryptedKey = 
            XMLUtils.getDirectChildElement(securityHeader, "EncryptedKey", WSConstants.ENC_NS);
        assertNotNull(encryptedKey);
        Element referenceList = 
            XMLUtils.getDirectChildElement(encryptedKey, "ReferenceList", WSConstants.ENC_NS);
        assertNotNull(referenceList);
        Node child = referenceList.getFirstChild();
        while (child != null) {
            if (child instanceof Element && "DataReference".equals(child.getLocalName())
                && WSConstants.ENC_NS.equals(child.getNamespaceURI())) {
                String uri = ((Element)child).getAttributeNS(null, "URI");
                if (uri.equals("#" + encryptedDataId)) {
                    referenceList.removeChild(child);
                    break;
                }
            }
            child = child.getNextSibling();
        }
        
        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.PrettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
            //System.out.println(outputString);
        }

        attachmentCallbackHandler = new AttachmentCallbackHandler(encryptedAttachments);
        verify(encryptedDoc, attachmentCallbackHandler);
        
        String processedDoc = XMLUtils.PrettyDocumentToString(encryptedDoc);
        assertTrue(processedDoc.contains(SOAP_BODY));
    }
    
    @org.junit.Test
    public void testEncryptedSOAPBody() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecEncrypt encrypt = new WSSecEncrypt();
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        AttachmentCallbackHandler outboundAttachmentCallback = new AttachmentCallbackHandler();
        encrypt.setAttachmentCallbackHandler(outboundAttachmentCallback);
        encrypt.setStoreBytesInAttachment(true);

        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        parts.add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Content"));
        encrypt.setParts(parts);

        Document encryptedDoc = encrypt.build(doc, crypto, secHeader);
        
        List<Attachment> encryptedAttachments = outboundAttachmentCallback.getResponseAttachments();
        assertNotNull(encryptedAttachments);
        // Should have EncryptedKey + EncryptedData stored in attachments...
        assertTrue(encryptedAttachments.size() == 2);
        
        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.PrettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
            // System.out.println(outputString);
        }

        AttachmentCallbackHandler inboundAttachmentCallback = 
            new AttachmentCallbackHandler(encryptedAttachments);
        verify(encryptedDoc, inboundAttachmentCallback);
        
        String processedDoc = XMLUtils.PrettyDocumentToString(encryptedDoc);
        assertTrue(processedDoc.contains(SOAP_BODY));
    }

    // Here we are storing the BinarySecurityToken bytes in an attachment
    @org.junit.Test
    public void testSignedSOAPBody() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        AttachmentCallbackHandler outboundAttachmentCallback = new AttachmentCallbackHandler();
        builder.setAttachmentCallbackHandler(outboundAttachmentCallback);
        builder.setStoreBytesInAttachment(true);
        
        Document signedDoc = builder.build(doc, crypto, secHeader);
        
        List<Attachment> signedAttachments = outboundAttachmentCallback.getResponseAttachments();
        assertNotNull(signedAttachments);
        assertTrue(signedAttachments.size() == 1);

        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString = 
                XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        AttachmentCallbackHandler inboundAttachmentCallback = 
            new AttachmentCallbackHandler(signedAttachments);
        verify(signedDoc, inboundAttachmentCallback);
    }
    
    @org.junit.Test
    public void testEncryptedHeaderAsEncryptedData() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAP_HEADER_MSG);
        WSSecEncrypt encrypt = new WSSecEncrypt();
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        AttachmentCallbackHandler outboundAttachmentCallback = new AttachmentCallbackHandler();
        encrypt.setAttachmentCallbackHandler(outboundAttachmentCallback);
        encrypt.setStoreBytesInAttachment(true);

        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        WSEncryptionPart encP =
            new WSEncryptionPart(
                "foobar", "urn:foo.bar", "");
        parts.add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Content"));
        parts.add(encP);
        encrypt.setParts(parts);

        Document encryptedDoc = encrypt.build(doc, crypto, secHeader);
        
        List<Attachment> encryptedAttachments = outboundAttachmentCallback.getResponseAttachments();
        assertNotNull(encryptedAttachments);
        // Should have EncryptedKey + EncryptedData + the header stored in attachments...
        assertTrue(encryptedAttachments.size() == 3);
        
        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.PrettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
            // System.out.println(outputString);
        }

        AttachmentCallbackHandler inboundAttachmentCallback = 
            new AttachmentCallbackHandler(encryptedAttachments);
        verify(encryptedDoc, inboundAttachmentCallback);
    }
    
    @org.junit.Test
    public void testEncryptedHeaderasEncryptedHeader() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAP_HEADER_MSG);
        WSSecEncrypt encrypt = new WSSecEncrypt();
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        AttachmentCallbackHandler outboundAttachmentCallback = new AttachmentCallbackHandler();
        encrypt.setAttachmentCallbackHandler(outboundAttachmentCallback);
        encrypt.setStoreBytesInAttachment(true);

        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        WSEncryptionPart encP =
            new WSEncryptionPart(
                "foobar", "urn:foo.bar", "Header");
        parts.add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Content"));
        parts.add(encP);
        encrypt.setParts(parts);

        Document encryptedDoc = encrypt.build(doc, crypto, secHeader);
        
        List<Attachment> encryptedAttachments = outboundAttachmentCallback.getResponseAttachments();
        assertNotNull(encryptedAttachments);
        // Should have EncryptedKey + EncryptedData + the header stored in attachments...
        assertTrue(encryptedAttachments.size() == 3);
        
        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.PrettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }

        AttachmentCallbackHandler inboundAttachmentCallback = 
            new AttachmentCallbackHandler(encryptedAttachments);
        verify(encryptedDoc, inboundAttachmentCallback);
    }
    
    @org.junit.Test
    public void testDerivedEncryptedSOAPBody() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        AttachmentCallbackHandler outboundAttachmentCallback = new AttachmentCallbackHandler();
        
        //EncryptedKey
        WSSecEncryptedKey encrKeyBuilder = new WSSecEncryptedKey();
        encrKeyBuilder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e");
        encrKeyBuilder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
        encrKeyBuilder.setAttachmentCallbackHandler(outboundAttachmentCallback);
        encrKeyBuilder.setStoreBytesInAttachment(true);
        encrKeyBuilder.prepare(doc, crypto);

        //Key information from the EncryptedKey
        byte[] ek = encrKeyBuilder.getEphemeralKey();
        String tokenIdentifier = encrKeyBuilder.getId();  

        //Derived key encryption
        WSSecDKEncrypt encrBuilder = new WSSecDKEncrypt();
        encrBuilder.setSymmetricEncAlgorithm(WSConstants.AES_128);
        encrBuilder.setExternalKey(ek, tokenIdentifier);
        encrBuilder.setAttachmentCallbackHandler(outboundAttachmentCallback);
        encrBuilder.setStoreBytesInAttachment(true);
        Document encryptedDoc = encrBuilder.build(doc, secHeader);

        encrKeyBuilder.prependToHeader(secHeader);
        encrKeyBuilder.prependBSTElementToHeader(secHeader);
        
        List<Attachment> encryptedAttachments = outboundAttachmentCallback.getResponseAttachments();
        assertNotNull(encryptedAttachments);
        // Should have EncryptedKey + EncryptedData stored in attachments...
        assertTrue(encryptedAttachments.size() == 2);
        
        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.PrettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
            // System.out.println(outputString);
        }

        AttachmentCallbackHandler inboundAttachmentCallback = 
            new AttachmentCallbackHandler(encryptedAttachments);
        verify(encryptedDoc, inboundAttachmentCallback);
        
        String processedDoc = XMLUtils.PrettyDocumentToString(encryptedDoc);
        assertTrue(processedDoc.contains(SOAP_BODY));
    }
    
    @org.junit.Test
    public void testDerivedSignedSOAPBody() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        AttachmentCallbackHandler outboundAttachmentCallback = new AttachmentCallbackHandler();
        
        //EncryptedKey
        WSSecEncryptedKey encrKeyBuilder = new WSSecEncryptedKey();
        encrKeyBuilder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e");
        encrKeyBuilder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
        encrKeyBuilder.setAttachmentCallbackHandler(outboundAttachmentCallback);
        encrKeyBuilder.setStoreBytesInAttachment(true);
        encrKeyBuilder.prepare(doc, crypto);

        //Key information from the EncryptedKey
        byte[] ek = encrKeyBuilder.getEphemeralKey();
        String tokenIdentifier = encrKeyBuilder.getId();  

        //Derived key encryption
        WSSecDKSign sigBuilder = new WSSecDKSign();
        sigBuilder.setExternalKey(ek, tokenIdentifier);
        sigBuilder.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
        sigBuilder.setAttachmentCallbackHandler(outboundAttachmentCallback);
        sigBuilder.setStoreBytesInAttachment(true);
        Document signedDoc = sigBuilder.build(doc, secHeader);

        encrKeyBuilder.prependToHeader(secHeader);
        encrKeyBuilder.prependBSTElementToHeader(secHeader);
        
        List<Attachment> signedAttachments = outboundAttachmentCallback.getResponseAttachments();
        assertNotNull(signedAttachments);
        assertTrue(signedAttachments.size() == 1);
        
        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        AttachmentCallbackHandler inboundAttachmentCallback = 
            new AttachmentCallbackHandler(signedAttachments);
        verify(signedDoc, inboundAttachmentCallback);
        
        String processedDoc = XMLUtils.PrettyDocumentToString(signedDoc);
        assertTrue(processedDoc.contains(SOAP_BODY));
    }
    
    @org.junit.Test
    public void testSignedEncryptedSOAPBody() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        AttachmentCallbackHandler outboundAttachmentCallback = new AttachmentCallbackHandler();
        
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        
        builder.setAttachmentCallbackHandler(outboundAttachmentCallback);
        builder.setStoreBytesInAttachment(true);
        builder.build(doc, crypto, secHeader);
        
        WSSecEncrypt encrypt = new WSSecEncrypt();
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        encrypt.setAttachmentCallbackHandler(outboundAttachmentCallback);
        encrypt.setStoreBytesInAttachment(true);

        Document encryptedDoc = encrypt.build(doc, crypto, secHeader);
        
        List<Attachment> encryptedAttachments = outboundAttachmentCallback.getResponseAttachments();
        assertNotNull(encryptedAttachments);
        assertTrue(encryptedAttachments.size() == 3);
        
        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.PrettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
            // System.out.println(outputString);
        }

        AttachmentCallbackHandler inboundAttachmentCallback = 
            new AttachmentCallbackHandler(encryptedAttachments);
        //WSHandlerResult results = verify(encryptedDoc, inboundAttachmentCallback);
        verify(encryptedDoc, inboundAttachmentCallback);
        
        String processedDoc = XMLUtils.PrettyDocumentToString(encryptedDoc);
        assertTrue(processedDoc.contains(SOAP_BODY));
        /*
        // Check Signature Element
        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.SIGN).get(0);
        @SuppressWarnings("unchecked")
        final List<WSDataRef> refs =
            (List<WSDataRef>) actionResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
        assertNotNull(refs);
        assertTrue(refs.size() == 1);
        WSDataRef wsDataRef = refs.get(0);
        Element protectedElement = wsDataRef.getProtectedElement();
        String outputString = DOM2Writer.nodeToString(protectedElement);
        System.out.println("ONE1: " + outputString);
        */
    }
    
    @org.junit.Test
    public void testEncryptedSignedSOAPBody() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        AttachmentCallbackHandler outboundAttachmentCallback = new AttachmentCallbackHandler();
        
        WSSecEncrypt encrypt = new WSSecEncrypt();
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        encrypt.setAttachmentCallbackHandler(outboundAttachmentCallback);
        encrypt.setStoreBytesInAttachment(true);

        encrypt.build(doc, crypto, secHeader);
        
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        
        builder.setAttachmentCallbackHandler(outboundAttachmentCallback);
        builder.setStoreBytesInAttachment(true);
        Document signedDoc = builder.build(doc, crypto, secHeader);
        
        List<Attachment> signedAttachments = outboundAttachmentCallback.getResponseAttachments();
        assertNotNull(signedAttachments);
        assertTrue(signedAttachments.size() == 3);
        
        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
            // System.out.println(outputString);
        }

        AttachmentCallbackHandler inboundAttachmentCallback = 
            new AttachmentCallbackHandler(signedAttachments);
        // WSHandlerResult results = verify(signedDoc, inboundAttachmentCallback);
        verify(signedDoc, inboundAttachmentCallback);
        
        String processedDoc = XMLUtils.PrettyDocumentToString(signedDoc);
        assertTrue(processedDoc.contains(SOAP_BODY));
        /*
        // Check Signature Element
        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.SIGN).get(0);
        @SuppressWarnings("unchecked")
        final List<WSDataRef> refs =
            (List<WSDataRef>) actionResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
        assertNotNull(refs);
        assertTrue(refs.size() == 1);
        WSDataRef wsDataRef = refs.get(0);
        Element protectedElement = wsDataRef.getProtectedElement();
        String outputString = DOM2Writer.nodeToString(protectedElement);
        System.out.println("TWO1: " + outputString);
        */
    }
    
    /**
     * Verifies the soap envelope.
     * This method verifies all the signature generated.
     *
     * @throws java.lang.Exception Thrown when there is a problem in verification
     */
    private List<WSSecurityEngineResult> verify(Document doc, CallbackHandler attachmentCallbackHandler) throws Exception {
        RequestData requestData = new RequestData();
        requestData.setAttachmentCallbackHandler(attachmentCallbackHandler);
        requestData.setSigVerCrypto(crypto);
        requestData.setDecCrypto(crypto);
        requestData.setCallbackHandler(new KeystoreCallbackHandler());
        return secEngine.processSecurityHeader(doc, null, requestData);
    }
}
