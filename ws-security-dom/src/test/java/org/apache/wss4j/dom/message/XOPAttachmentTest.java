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
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import javax.security.auth.callback.CallbackHandler;

import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.WSS4JConstants;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.Attachment;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.common.CustomHandler;
import org.apache.wss4j.dom.common.KeystoreCallbackHandler;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.handler.HandlerAction;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.junit.Test;
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
    private Crypto crypto;

    public XOPAttachmentTest() throws Exception {
        WSSConfig.init();
        crypto = CryptoFactory.getInstance();
    }

    protected byte[] readInputStream(InputStream inputStream) throws IOException {
        try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
            int read = 0;
            byte[] buf = new byte[4096];
            while ((read = inputStream.read(buf)) != -1) {
                byteArrayOutputStream.write(buf, 0, read);
            }
            return byteArrayOutputStream.toByteArray();
        }
    }

    // Set up a test to encrypt the SOAP Body + an attachment, which is the same content as
    // the SOAP Body. Then replace the encrypted SOAP Body with a xop:Include to the attachment,
    // and modify the request to remove the encryption stuff pointing to the attachment.
    // (NOTE: This test was before we supported creating requests with xop:Include)
    @Test
    public void testManualEncryptedSOAPBody() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecEncrypt encrypt = new WSSecEncrypt(secHeader);
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        encrypt.getParts().add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Content"));
        encrypt.getParts().add(new WSEncryptionPart("cid:Attachments", "Content"));

        String attachmentId = UUID.randomUUID().toString();
        final Attachment attachment = new Attachment();
        attachment.setId(attachmentId);
        attachment.setSourceStream(new ByteArrayInputStream(SOAP_BODY.getBytes(StandardCharsets.UTF_8)));

        AttachmentCallbackHandler attachmentCallbackHandler =
            new AttachmentCallbackHandler(Collections.singletonList(attachment));
        encrypt.setAttachmentCallbackHandler(attachmentCallbackHandler);
        List<Attachment> encryptedAttachments = attachmentCallbackHandler.getResponseAttachments();

        Document encryptedDoc = encrypt.build(crypto);

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

        XMLUtils.setNamespace(cipherValue, WSS4JConstants.XOP_NS, "xop");

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
            String outputString = XMLUtils.prettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
            //System.out.println(outputString);
        }

        attachmentCallbackHandler = new AttachmentCallbackHandler(encryptedAttachments);
        verify(encryptedDoc, attachmentCallbackHandler);

        String processedDoc = XMLUtils.prettyDocumentToString(encryptedDoc);
        assertTrue(processedDoc.contains(SOAP_BODY));
    }

    @Test
    public void testEncryptedSOAPBody() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecEncrypt encrypt = new WSSecEncrypt(secHeader);
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        AttachmentCallbackHandler outboundAttachmentCallback = new AttachmentCallbackHandler();
        encrypt.setAttachmentCallbackHandler(outboundAttachmentCallback);
        encrypt.setStoreBytesInAttachment(true);

        encrypt.getParts().add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Content"));

        Document encryptedDoc = encrypt.build(crypto);

        List<Attachment> encryptedAttachments = outboundAttachmentCallback.getResponseAttachments();
        assertNotNull(encryptedAttachments);
        // Should have EncryptedKey + EncryptedData stored in attachments...
        assertTrue(encryptedAttachments.size() == 2);

        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.prettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
            // System.out.println(outputString);
        }

        AttachmentCallbackHandler inboundAttachmentCallback =
            new AttachmentCallbackHandler(encryptedAttachments);
        verify(encryptedDoc, inboundAttachmentCallback);

        String processedDoc = XMLUtils.prettyDocumentToString(encryptedDoc);
        assertTrue(processedDoc.contains(SOAP_BODY));
    }

    // Here we are storing the BinarySecurityToken bytes in an attachment
    @Test
    public void testSignedSOAPBody() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecSignature builder = new WSSecSignature(secHeader);
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);

        AttachmentCallbackHandler outboundAttachmentCallback = new AttachmentCallbackHandler();
        builder.setAttachmentCallbackHandler(outboundAttachmentCallback);
        builder.setStoreBytesInAttachment(true);

        Document signedDoc = builder.build(crypto);

        List<Attachment> signedAttachments = outboundAttachmentCallback.getResponseAttachments();
        assertNotNull(signedAttachments);
        assertTrue(signedAttachments.size() == 1);

        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        AttachmentCallbackHandler inboundAttachmentCallback =
            new AttachmentCallbackHandler(signedAttachments);
        verify(signedDoc, inboundAttachmentCallback);
    }

    @Test
    public void testSignedSOAPBodyAndBinarySecurityToken() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecSignature builder = new WSSecSignature(secHeader);
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        builder.setIncludeSignatureToken(true);

        AttachmentCallbackHandler outboundAttachmentCallback = new AttachmentCallbackHandler();
        builder.setAttachmentCallbackHandler(outboundAttachmentCallback);
        builder.setStoreBytesInAttachment(true);

        Document signedDoc = builder.build(crypto);

        List<Attachment> signedAttachments = outboundAttachmentCallback.getResponseAttachments();
        assertNotNull(signedAttachments);
        assertTrue(signedAttachments.size() == 1);

        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        AttachmentCallbackHandler inboundAttachmentCallback =
            new AttachmentCallbackHandler(signedAttachments);
        verify(signedDoc, inboundAttachmentCallback);
    }

    @Test
    public void testEncryptedHeaderAsEncryptedData() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAP_HEADER_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecEncrypt encrypt = new WSSecEncrypt(secHeader);
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        AttachmentCallbackHandler outboundAttachmentCallback = new AttachmentCallbackHandler();
        encrypt.setAttachmentCallbackHandler(outboundAttachmentCallback);
        encrypt.setStoreBytesInAttachment(true);

        WSEncryptionPart encP =
            new WSEncryptionPart(
                "foobar", "urn:foo.bar", "");
        encrypt.getParts().add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Content"));
        encrypt.getParts().add(encP);

        Document encryptedDoc = encrypt.build(crypto);

        List<Attachment> encryptedAttachments = outboundAttachmentCallback.getResponseAttachments();
        assertNotNull(encryptedAttachments);
        // Should have EncryptedKey + EncryptedData + the header stored in attachments...
        assertTrue(encryptedAttachments.size() == 3);

        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.prettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
            // System.out.println(outputString);
        }

        AttachmentCallbackHandler inboundAttachmentCallback =
            new AttachmentCallbackHandler(encryptedAttachments);
        verify(encryptedDoc, inboundAttachmentCallback);
    }

    @Test
    public void testEncryptedHeaderasEncryptedHeader() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAP_HEADER_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecEncrypt encrypt = new WSSecEncrypt(secHeader);
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        AttachmentCallbackHandler outboundAttachmentCallback = new AttachmentCallbackHandler();
        encrypt.setAttachmentCallbackHandler(outboundAttachmentCallback);
        encrypt.setStoreBytesInAttachment(true);

        WSEncryptionPart encP =
            new WSEncryptionPart(
                "foobar", "urn:foo.bar", "Header");
        encrypt.getParts().add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Content"));
        encrypt.getParts().add(encP);

        Document encryptedDoc = encrypt.build(crypto);

        List<Attachment> encryptedAttachments = outboundAttachmentCallback.getResponseAttachments();
        assertNotNull(encryptedAttachments);
        // Should have EncryptedKey + EncryptedData + the header stored in attachments...
        assertTrue(encryptedAttachments.size() == 3);

        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.prettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }

        AttachmentCallbackHandler inboundAttachmentCallback =
            new AttachmentCallbackHandler(encryptedAttachments);
        verify(encryptedDoc, inboundAttachmentCallback);
    }

    @Test
    public void testDerivedEncryptedSOAPBody() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        AttachmentCallbackHandler outboundAttachmentCallback = new AttachmentCallbackHandler();

        //EncryptedKey
        WSSecEncryptedKey encrKeyBuilder = new WSSecEncryptedKey(secHeader);
        encrKeyBuilder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e");
        encrKeyBuilder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
        encrKeyBuilder.setAttachmentCallbackHandler(outboundAttachmentCallback);
        encrKeyBuilder.setStoreBytesInAttachment(true);
        encrKeyBuilder.prepare(crypto);

        //Key information from the EncryptedKey
        byte[] ek = encrKeyBuilder.getEphemeralKey();
        String tokenIdentifier = encrKeyBuilder.getId();

        //Derived key encryption
        WSSecDKEncrypt encrBuilder = new WSSecDKEncrypt(secHeader);
        encrBuilder.setSymmetricEncAlgorithm(WSConstants.AES_128);
        encrBuilder.setExternalKey(ek, tokenIdentifier);
        encrBuilder.setAttachmentCallbackHandler(outboundAttachmentCallback);
        encrBuilder.setStoreBytesInAttachment(true);
        Document encryptedDoc = encrBuilder.build();

        encrKeyBuilder.prependToHeader();
        encrKeyBuilder.prependBSTElementToHeader();

        List<Attachment> encryptedAttachments = outboundAttachmentCallback.getResponseAttachments();
        assertNotNull(encryptedAttachments);
        // Should have EncryptedKey + EncryptedData stored in attachments...
        assertTrue(encryptedAttachments.size() == 2);

        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.prettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
            // System.out.println(outputString);
        }

        AttachmentCallbackHandler inboundAttachmentCallback =
            new AttachmentCallbackHandler(encryptedAttachments);
        verify(encryptedDoc, inboundAttachmentCallback);

        String processedDoc = XMLUtils.prettyDocumentToString(encryptedDoc);
        assertTrue(processedDoc.contains(SOAP_BODY));
    }

    @Test
    public void testDerivedSignedSOAPBody() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        AttachmentCallbackHandler outboundAttachmentCallback = new AttachmentCallbackHandler();

        //EncryptedKey
        WSSecEncryptedKey encrKeyBuilder = new WSSecEncryptedKey(secHeader);
        encrKeyBuilder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e");
        encrKeyBuilder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
        encrKeyBuilder.setAttachmentCallbackHandler(outboundAttachmentCallback);
        encrKeyBuilder.setStoreBytesInAttachment(true);
        encrKeyBuilder.prepare(crypto);

        //Key information from the EncryptedKey
        byte[] ek = encrKeyBuilder.getEphemeralKey();
        String tokenIdentifier = encrKeyBuilder.getId();

        //Derived key encryption
        WSSecDKSign sigBuilder = new WSSecDKSign(secHeader);
        sigBuilder.setExternalKey(ek, tokenIdentifier);
        sigBuilder.setSignatureAlgorithm(WSConstants.HMAC_SHA1);
        sigBuilder.setAttachmentCallbackHandler(outboundAttachmentCallback);
        sigBuilder.setStoreBytesInAttachment(true);
        Document signedDoc = sigBuilder.build();

        encrKeyBuilder.prependToHeader();
        encrKeyBuilder.prependBSTElementToHeader();

        List<Attachment> signedAttachments = outboundAttachmentCallback.getResponseAttachments();
        assertNotNull(signedAttachments);
        assertTrue(signedAttachments.size() == 1);

        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        AttachmentCallbackHandler inboundAttachmentCallback =
            new AttachmentCallbackHandler(signedAttachments);
        verify(signedDoc, inboundAttachmentCallback);

        String processedDoc = XMLUtils.prettyDocumentToString(signedDoc);
        assertTrue(processedDoc.contains(SOAP_BODY));
    }

    @Test
    public void testSignedEncryptedSOAPBody() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        AttachmentCallbackHandler outboundAttachmentCallback = new AttachmentCallbackHandler();

        WSSecSignature builder = new WSSecSignature(secHeader);
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);

        builder.setAttachmentCallbackHandler(outboundAttachmentCallback);
        builder.setStoreBytesInAttachment(true);
        builder.getParts().add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Content"));
        builder.build(crypto);

        WSSecEncrypt encrypt = new WSSecEncrypt(secHeader);
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        encrypt.setAttachmentCallbackHandler(outboundAttachmentCallback);
        encrypt.setStoreBytesInAttachment(true);
        encrypt.getParts().add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Content"));

        Document encryptedDoc = encrypt.build(crypto);

        List<Attachment> encryptedAttachments = outboundAttachmentCallback.getResponseAttachments();
        assertNotNull(encryptedAttachments);
        assertTrue(encryptedAttachments.size() == 3);

        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.prettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
            // System.out.println(outputString);
        }

        AttachmentCallbackHandler inboundAttachmentCallback =
            new AttachmentCallbackHandler(encryptedAttachments);
        verify(encryptedDoc, inboundAttachmentCallback);

        String processedDoc = XMLUtils.prettyDocumentToString(encryptedDoc);
        assertTrue(processedDoc.contains(SOAP_BODY));
    }

    @Test
    public void testSignedEncryptedSOAPBodyViaHandler() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        reqData.setUsername("16c73ab6-b892-458f-abf5-2f875f74882e");

        AttachmentCallbackHandler outboundAttachmentCallback = new AttachmentCallbackHandler();
        reqData.setAttachmentCallbackHandler(outboundAttachmentCallback);


        java.util.Map<String, Object> config = new java.util.TreeMap<>();
        config.put(WSHandlerConstants.SIG_PROP_FILE, "crypto.properties");
        config.put(WSHandlerConstants.ENC_PROP_FILE, "crypto.properties");
        config.put(WSHandlerConstants.SIG_KEY_ID, "DirectReference");
        config.put("password", "security");
        config.put(WSHandlerConstants.STORE_BYTES_IN_ATTACHMENT, "true");
        reqData.setMsgContext(config);

        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        List<HandlerAction> actions = new ArrayList<>();
        actions.add(new HandlerAction(WSConstants.SIGN));
        actions.add(new HandlerAction(WSConstants.ENCR));

        handler.send(
            doc,
            reqData,
            actions,
            true
        );
        String outputString =
            XMLUtils.prettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed message:");
            LOG.debug(outputString);
        }

        List<Attachment> encryptedAttachments = outboundAttachmentCallback.getResponseAttachments();
        assertNotNull(encryptedAttachments);
        assertTrue(encryptedAttachments.size() == 3);

        AttachmentCallbackHandler inboundAttachmentCallback =
            new AttachmentCallbackHandler(encryptedAttachments);
        verify(doc, inboundAttachmentCallback);

        String processedDoc = XMLUtils.prettyDocumentToString(doc);
        assertTrue(processedDoc.contains(SOAP_BODY));
    }

    @Test
    public void testEncryptedSignedSOAPBodyViaHandler() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        reqData.setUsername("16c73ab6-b892-458f-abf5-2f875f74882e");

        AttachmentCallbackHandler outboundAttachmentCallback = new AttachmentCallbackHandler();
        reqData.setAttachmentCallbackHandler(outboundAttachmentCallback);


        java.util.Map<String, Object> config = new java.util.TreeMap<>();
        config.put(WSHandlerConstants.SIG_PROP_FILE, "crypto.properties");
        config.put(WSHandlerConstants.ENC_PROP_FILE, "crypto.properties");
        config.put(WSHandlerConstants.SIG_KEY_ID, "DirectReference");
        config.put("password", "security");
        config.put(WSHandlerConstants.STORE_BYTES_IN_ATTACHMENT, "true");
        reqData.setMsgContext(config);

        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        List<HandlerAction> actions = new ArrayList<>();
        actions.add(new HandlerAction(WSConstants.ENCR));
        actions.add(new HandlerAction(WSConstants.SIGN));

        handler.send(
            doc,
            reqData,
            actions,
            true
        );
        String outputString =
            XMLUtils.prettyDocumentToString(doc);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed message:");
            LOG.debug(outputString);
        }

        List<Attachment> encryptedAttachments = outboundAttachmentCallback.getResponseAttachments();
        assertNotNull(encryptedAttachments);
        assertTrue(encryptedAttachments.isEmpty());

        AttachmentCallbackHandler inboundAttachmentCallback =
            new AttachmentCallbackHandler(encryptedAttachments);
        verify(doc, inboundAttachmentCallback);

        String processedDoc = XMLUtils.prettyDocumentToString(doc);
        assertTrue(processedDoc.contains(SOAP_BODY));
    }

    /**
     * Verifies the soap envelope.
     * This method verifies all the signature generated.
     *
     * @throws java.lang.Exception Thrown when there is a problem in verification
     */
    private WSHandlerResult verify(Document doc, CallbackHandler attachmentCallbackHandler) throws Exception {
        RequestData requestData = new RequestData();
        requestData.setAttachmentCallbackHandler(attachmentCallbackHandler);
        requestData.setSigVerCrypto(crypto);
        requestData.setDecCrypto(crypto);
        requestData.setCallbackHandler(new KeystoreCallbackHandler());
        return secEngine.processSecurityHeader(doc, requestData);
    }
}
