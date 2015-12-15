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
import java.io.PushbackInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.Attachment;
import org.apache.wss4j.common.ext.AttachmentRequestCallback;
import org.apache.wss4j.common.ext.AttachmentResultCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.AttachmentUtils;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.common.KeystoreCallbackHandler;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.junit.Assert;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

public class AttachmentTest extends Assert {

    private static final org.slf4j.Logger LOG =
            org.slf4j.LoggerFactory.getLogger(AttachmentTest.class);

    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private Crypto crypto = null;

    public AttachmentTest() throws Exception {
        WSSConfig.init();
        crypto = CryptoFactory.getInstance();
    }

    protected Map<String, String> getHeaders(String attachmentId) {
        Map<String, String> headers = new HashMap<>();
        headers.put(AttachmentUtils.MIME_HEADER_CONTENT_DESCRIPTION, "Attachment");
        headers.put(AttachmentUtils.MIME_HEADER_CONTENT_DISPOSITION, "attachment; filename=\"fname.ext\"");
        headers.put(AttachmentUtils.MIME_HEADER_CONTENT_ID, "<attachment=" + attachmentId + ">");
        headers.put(AttachmentUtils.MIME_HEADER_CONTENT_LOCATION, "http://ws.apache.org");
        headers.put(AttachmentUtils.MIME_HEADER_CONTENT_TYPE, "text/xml; charset=UTF-8");
        headers.put("TestHeader", "testHeaderValue");
        return headers;
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

    @org.junit.Test
    public void testXMLAttachmentContentSignature() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");

        builder.getParts().add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Content"));
        builder.getParts().add(new WSEncryptionPart("cid:Attachments", "Content"));

        final String attachmentId = UUID.randomUUID().toString();
        final Attachment attachment = new Attachment();
        attachment.setMimeType("text/xml");
        attachment.addHeaders(getHeaders(attachmentId));
        attachment.setId(attachmentId);
        attachment.setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes(StandardCharsets.UTF_8)));

        AttachmentCallbackHandler attachmentCallbackHandler =
            new AttachmentCallbackHandler(Collections.singletonList(attachment));
        builder.setAttachmentCallbackHandler(attachmentCallbackHandler);

        LOG.info("Before Signing....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        Document signedDoc = builder.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString = XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        NodeList sigReferences = signedDoc.getElementsByTagNameNS(WSConstants.SIG_NS, "Reference");
        Assert.assertEquals(2, sigReferences.getLength());

        attachmentCallbackHandler =
            new AttachmentCallbackHandler(Collections.singletonList(attachment));
        verify(signedDoc, attachmentCallbackHandler);

        Assert.assertFalse(attachmentCallbackHandler.getResponseAttachments().isEmpty());
        Attachment responseAttachment = attachmentCallbackHandler.getResponseAttachments().get(0);
        byte[] attachmentBytes = readInputStream(responseAttachment.getSourceStream());
        Assert.assertTrue(Arrays.equals(attachmentBytes, SOAPUtil.SAMPLE_SOAP_MSG.getBytes(StandardCharsets.UTF_8)));
        Assert.assertEquals("text/xml", responseAttachment.getMimeType());
    }

    @org.junit.Test
    public void testInvalidXMLAttachmentContentSignature() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");

        builder.getParts().add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Content"));
        builder.getParts().add(new WSEncryptionPart("cid:Attachments", "Content"));

        final String attachmentId = UUID.randomUUID().toString();
        final Attachment attachment = new Attachment();
        attachment.setMimeType("text/xml");
        attachment.addHeaders(getHeaders(attachmentId));
        attachment.setId(attachmentId);
        attachment.setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes(StandardCharsets.UTF_8)));

        AttachmentCallbackHandler attachmentCallbackHandler =
            new AttachmentCallbackHandler(Collections.singletonList(attachment));
        builder.setAttachmentCallbackHandler(attachmentCallbackHandler);

        LOG.info("Before Signing....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        Document signedDoc = builder.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString = XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        try {
            verify(signedDoc, new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof AttachmentRequestCallback) {
                        AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callbacks[0];

                        if (!attachment.getId().equals(attachmentRequestCallback.getAttachmentId())) {
                            throw new RuntimeException("wrong attachment requested");
                        }

                        List<Attachment> attachments = new ArrayList<>();
                        attachment.setSourceStream(new ByteArrayInputStream(
                                SOAPUtil.SAMPLE_SOAP_MSG.replace("15", "16").getBytes(StandardCharsets.UTF_8)));
                        attachments.add(attachment);
                        attachmentRequestCallback.setAttachments(attachments);
                    }
                }
            });
            Assert.fail();
        } catch (WSSecurityException e) {
            Assert.assertEquals(e.getMessage(), "The signature or decryption was invalid");
        }
    }

    @org.junit.Test
    public void testXMLAttachmentCompleteSignature() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");

        builder.getParts().add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Content"));
        builder.getParts().add(new WSEncryptionPart("cid:Attachments", "Element"));

        final String attachmentId = UUID.randomUUID().toString();
        final Attachment attachment = new Attachment();
        attachment.setMimeType("text/xml");
        attachment.addHeaders(getHeaders(attachmentId));
        attachment.setId(attachmentId);
        attachment.setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes(StandardCharsets.UTF_8)));

        AttachmentCallbackHandler attachmentCallbackHandler =
            new AttachmentCallbackHandler(Collections.singletonList(attachment));
        builder.setAttachmentCallbackHandler(attachmentCallbackHandler);

        LOG.info("Before Signing....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        Document signedDoc = builder.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString = XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        NodeList sigReferences = signedDoc.getElementsByTagNameNS(WSConstants.SIG_NS, "Reference");
        Assert.assertEquals(2, sigReferences.getLength());

        attachmentCallbackHandler =
            new AttachmentCallbackHandler(Collections.singletonList(attachment));
        verify(signedDoc, attachmentCallbackHandler);

        Assert.assertFalse(attachmentCallbackHandler.getResponseAttachments().isEmpty());
        Attachment responseAttachment = attachmentCallbackHandler.getResponseAttachments().get(0);
        byte[] attachmentBytes = readInputStream(responseAttachment.getSourceStream());
        Assert.assertTrue(Arrays.equals(attachmentBytes, SOAPUtil.SAMPLE_SOAP_MSG.getBytes(StandardCharsets.UTF_8)));
        Assert.assertEquals("text/xml", responseAttachment.getMimeType());
    }

    @org.junit.Test
    public void testInvalidXMLAttachmentCompleteSignature() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");

        builder.getParts().add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Content"));
        builder.getParts().add(new WSEncryptionPart("cid:Attachments", "Element"));

        final String attachmentId = UUID.randomUUID().toString();
        final Attachment attachment = new Attachment();
        attachment.setMimeType("text/xml");
        attachment.addHeaders(getHeaders(attachmentId));
        attachment.setId(attachmentId);
        attachment.setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes(StandardCharsets.UTF_8)));

        AttachmentCallbackHandler attachmentCallbackHandler =
            new AttachmentCallbackHandler(Collections.singletonList(attachment));
        builder.setAttachmentCallbackHandler(attachmentCallbackHandler);

        LOG.info("Before Signing....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        Document signedDoc = builder.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString = XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        try {
            attachment.addHeader(AttachmentUtils.MIME_HEADER_CONTENT_DESCRIPTION, "Kaputt");
            verify(signedDoc, new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof AttachmentRequestCallback) {
                        AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callbacks[0];

                        if (!attachment.getId().equals(attachmentRequestCallback.getAttachmentId())) {
                            throw new RuntimeException("wrong attachment requested");
                        }

                        List<Attachment> attachments = new ArrayList<>();
                        attachments.add(attachment);
                        attachmentRequestCallback.setAttachments(attachments);
                    }
                }
            });
            Assert.fail();
        } catch (WSSecurityException e) {
            Assert.assertEquals(e.getMessage(), "The signature or decryption was invalid");
        }
    }

    @org.junit.Test
    public void testMultipleAttachmentCompleteSignature() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");

        builder.getParts().add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Content"));
        builder.getParts().add(new WSEncryptionPart("cid:Attachments", "Element"));

        final String attachment1Id = UUID.randomUUID().toString();
        final Attachment[] attachment = new Attachment[2];
        attachment[0] = new Attachment();
        attachment[0].setMimeType("text/xml");
        attachment[0].addHeaders(getHeaders(attachment1Id));
        attachment[0].setId(attachment1Id);
        attachment[0].setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes(StandardCharsets.UTF_8)));

        final String attachment2Id = UUID.randomUUID().toString();
        attachment[1] = new Attachment();
        attachment[1].setMimeType("text/plain");
        attachment[1].addHeaders(getHeaders(attachment2Id));
        attachment[1].setId(attachment2Id);
        attachment[1].setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes(StandardCharsets.UTF_8)));

        AttachmentCallbackHandler attachmentCallbackHandler =
            new AttachmentCallbackHandler(Arrays.asList(attachment));
        builder.setAttachmentCallbackHandler(attachmentCallbackHandler);

        LOG.info("Before Signing....");
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();
        Document signedDoc = builder.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            LOG.debug("After Signing....");
            String outputString = XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        NodeList sigReferences = signedDoc.getElementsByTagNameNS(WSConstants.SIG_NS, "Reference");
        Assert.assertEquals(3, sigReferences.getLength());

        attachmentCallbackHandler = new AttachmentCallbackHandler(Arrays.asList(attachment));
        verify(signedDoc, attachmentCallbackHandler);

        Assert.assertFalse(attachmentCallbackHandler.getResponseAttachments().isEmpty());
        Attachment responseAttachment = attachmentCallbackHandler.getResponseAttachments().get(0);
        byte[] attachment1Bytes = readInputStream(responseAttachment.getSourceStream());
        Assert.assertTrue(Arrays.equals(attachment1Bytes, SOAPUtil.SAMPLE_SOAP_MSG.getBytes(StandardCharsets.UTF_8)));
        Assert.assertEquals("text/xml", responseAttachment.getMimeType());

        responseAttachment = attachmentCallbackHandler.getResponseAttachments().get(1);
        byte[] attachment2Bytes = readInputStream(responseAttachment.getSourceStream());
        Assert.assertTrue(Arrays.equals(attachment2Bytes, SOAPUtil.SAMPLE_SOAP_MSG.getBytes(StandardCharsets.UTF_8)));
        Assert.assertEquals("text/plain", responseAttachment.getMimeType());
    }

    @org.junit.Test
    public void testXMLAttachmentContentEncryption() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecEncrypt encrypt = new WSSecEncrypt();
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        encrypt.getParts().add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Content"));
        encrypt.getParts().add(new WSEncryptionPart("cid:Attachments", "Content"));

        String attachmentId = UUID.randomUUID().toString();
        final Attachment attachment = new Attachment();
        attachment.setMimeType("text/xml");
        attachment.addHeaders(getHeaders(attachmentId));
        attachment.setId(attachmentId);
        attachment.setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes(StandardCharsets.UTF_8)));

        AttachmentCallbackHandler attachmentCallbackHandler =
            new AttachmentCallbackHandler(Collections.singletonList(attachment));
        encrypt.setAttachmentCallbackHandler(attachmentCallbackHandler);
        List<Attachment> encryptedAttachments = attachmentCallbackHandler.getResponseAttachments();

        Document encryptedDoc = encrypt.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.PrettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }

        NodeList references = doc.getElementsByTagNameNS(WSConstants.ENC_NS, "DataReference");
        Assert.assertEquals(2, references.getLength());
        NodeList cipherReferences = doc.getElementsByTagNameNS(WSConstants.ENC_NS, "CipherReference");
        Assert.assertEquals(1, cipherReferences.getLength());
        NodeList encDatas = doc.getElementsByTagNameNS(WSConstants.ENC_NS, "EncryptedData");
        Assert.assertEquals(2, encDatas.getLength());

        NodeList securityHeaderElement = doc.getElementsByTagNameNS(WSConstants.WSSE_NS, "Security");
        Assert.assertEquals(1, securityHeaderElement.getLength());
        NodeList childs = securityHeaderElement.item(0).getChildNodes();
        Assert.assertEquals(2, childs.getLength());
        Assert.assertEquals(childs.item(0).getLocalName(), "EncryptedKey");
        Assert.assertEquals(childs.item(1).getLocalName(), "EncryptedData");

        attachmentCallbackHandler = new AttachmentCallbackHandler(encryptedAttachments);
        verify(encryptedDoc, attachmentCallbackHandler);

        Assert.assertFalse(attachmentCallbackHandler.getResponseAttachments().isEmpty());
        Attachment responseAttachment = attachmentCallbackHandler.getResponseAttachments().get(0);
        byte[] attachmentBytes = readInputStream(responseAttachment.getSourceStream());
        Assert.assertTrue(Arrays.equals(attachmentBytes, SOAPUtil.SAMPLE_SOAP_MSG.getBytes(StandardCharsets.UTF_8)));
        Assert.assertEquals("text/xml", responseAttachment.getMimeType());

        Map<String, String> attHeaders = responseAttachment.getHeaders();
        Assert.assertEquals(6, attHeaders.size());
    }

    @org.junit.Test
    public void testInvalidXMLAttachmentContentEncryption() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecEncrypt encrypt = new WSSecEncrypt();
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        encrypt.getParts().add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Content"));
        encrypt.getParts().add(new WSEncryptionPart("cid:Attachments", "Content"));

        String attachmentId = UUID.randomUUID().toString();
        final Attachment attachment = new Attachment();
        attachment.setMimeType("text/xml");
        attachment.addHeaders(getHeaders(attachmentId));
        attachment.setId(attachmentId);
        attachment.setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes(StandardCharsets.UTF_8)));

        AttachmentCallbackHandler attachmentCallbackHandler =
            new AttachmentCallbackHandler(Collections.singletonList(attachment));
        encrypt.setAttachmentCallbackHandler(attachmentCallbackHandler);
        List<Attachment> encryptedAttachments = attachmentCallbackHandler.getResponseAttachments();

        Document encryptedDoc = encrypt.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.PrettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }

        final PushbackInputStream pis =
            new PushbackInputStream(encryptedAttachments.get(0).getSourceStream(), 1);
        pis.unread('K');
        encryptedAttachments.get(0).setSourceStream(pis);

        attachmentCallbackHandler = new AttachmentCallbackHandler(encryptedAttachments);
        verify(encryptedDoc, attachmentCallbackHandler);

        Assert.assertFalse(attachmentCallbackHandler.getResponseAttachments().isEmpty());
        Attachment responseAttachment = attachmentCallbackHandler.getResponseAttachments().get(0);
        // Different behaviour here for different JDKs...
        try {
            byte[] attachmentBytes = readInputStream(responseAttachment.getSourceStream());
            Assert.assertFalse(Arrays.equals(attachmentBytes, SOAPUtil.SAMPLE_SOAP_MSG.getBytes(StandardCharsets.UTF_8)));
            Assert.assertEquals("text/xml", responseAttachment.getMimeType());

            Map<String, String> attHeaders = responseAttachment.getHeaders();
            Assert.assertEquals(6, attHeaders.size());
        } catch (IOException ex) { //NOPMD
            // expected
        }
    }

    @org.junit.Test
    public void testXMLAttachmentContentEncryptionExternalReferenceList() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecEncrypt encrypt = new WSSecEncrypt();
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        encrypt.getParts().add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Content"));
        encrypt.getParts().add(new WSEncryptionPart("cid:Attachments", "Content"));

        String attachmentId = UUID.randomUUID().toString();
        final Attachment attachment = new Attachment();
        attachment.setMimeType("text/xml");
        attachment.addHeaders(getHeaders(attachmentId));
        attachment.setId(attachmentId);
        attachment.setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes(StandardCharsets.UTF_8)));

        AttachmentCallbackHandler attachmentCallbackHandler =
            new AttachmentCallbackHandler(Collections.singletonList(attachment));
        encrypt.setAttachmentCallbackHandler(attachmentCallbackHandler);
        List<Attachment> encryptedAttachments = attachmentCallbackHandler.getResponseAttachments();

        encrypt.prepare(doc, crypto);
        Element refs = encrypt.encrypt();
        encrypt.addAttachmentEncryptedDataElements(secHeader);
        encrypt.addExternalRefElement(refs, secHeader);
        encrypt.prependToHeader(secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        NodeList references = doc.getElementsByTagNameNS(WSConstants.ENC_NS, "DataReference");
        Assert.assertEquals(2, references.getLength());
        NodeList cipherReferences = doc.getElementsByTagNameNS(WSConstants.ENC_NS, "CipherReference");
        Assert.assertEquals(1, cipherReferences.getLength());
        NodeList encDatas = doc.getElementsByTagNameNS(WSConstants.ENC_NS, "EncryptedData");
        Assert.assertEquals(2, encDatas.getLength());

        NodeList securityHeaderElement = doc.getElementsByTagNameNS(WSConstants.WSSE_NS, "Security");
        Assert.assertEquals(1, securityHeaderElement.getLength());
        NodeList childs = securityHeaderElement.item(0).getChildNodes();
        Assert.assertEquals(3, childs.getLength());
        Assert.assertEquals(childs.item(0).getLocalName(), "EncryptedKey");
        Assert.assertEquals(childs.item(1).getLocalName(), "ReferenceList");
        Assert.assertEquals(childs.item(2).getLocalName(), "EncryptedData");

        attachmentCallbackHandler = new AttachmentCallbackHandler(encryptedAttachments);
        verify(doc, attachmentCallbackHandler);

        Assert.assertFalse(attachmentCallbackHandler.getResponseAttachments().isEmpty());
        Attachment responseAttachment = attachmentCallbackHandler.getResponseAttachments().get(0);

        byte[] attachmentBytes = readInputStream(responseAttachment.getSourceStream());
        Assert.assertTrue(Arrays.equals(attachmentBytes, SOAPUtil.SAMPLE_SOAP_MSG.getBytes(StandardCharsets.UTF_8)));
        Assert.assertEquals("text/xml", responseAttachment.getMimeType());

        Map<String, String> attHeaders = responseAttachment.getHeaders();
        Assert.assertEquals(6, attHeaders.size());
    }

    @org.junit.Test
    public void testXMLAttachmentContentEncryptionNoReference() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecEncrypt encrypt = new WSSecEncrypt();
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        encrypt.getParts().add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Content"));
        encrypt.getParts().add(new WSEncryptionPart("cid:Attachments", "Content"));

        String attachmentId = UUID.randomUUID().toString();
        final Attachment attachment =  new Attachment();
        attachment.setMimeType("text/xml");
        attachment.addHeaders(getHeaders(attachmentId));
        attachment.setId(attachmentId);
        attachment.setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes(StandardCharsets.UTF_8)));

        AttachmentCallbackHandler attachmentCallbackHandler =
            new AttachmentCallbackHandler(Collections.singletonList(attachment));
        encrypt.setAttachmentCallbackHandler(attachmentCallbackHandler);
        List<Attachment> encryptedAttachments = attachmentCallbackHandler.getResponseAttachments();

        encrypt.prepare(doc, crypto);
        encrypt.encrypt();
        encrypt.addAttachmentEncryptedDataElements(secHeader);
        //encrypt.addExternalRefElement(refs, secHeader);
        encrypt.prependToHeader(secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        NodeList references = doc.getElementsByTagNameNS(WSConstants.ENC_NS, "DataReference");
        Assert.assertEquals(0, references.getLength());
        NodeList cipherReferences = doc.getElementsByTagNameNS(WSConstants.ENC_NS, "CipherReference");
        Assert.assertEquals(1, cipherReferences.getLength());
        NodeList encDatas = doc.getElementsByTagNameNS(WSConstants.ENC_NS, "EncryptedData");
        Assert.assertEquals(2, encDatas.getLength());

        NodeList securityHeaderElement = doc.getElementsByTagNameNS(WSConstants.WSSE_NS, "Security");
        Assert.assertEquals(1, securityHeaderElement.getLength());
        NodeList childs = securityHeaderElement.item(0).getChildNodes();
        Assert.assertEquals(2, childs.getLength());
        Assert.assertEquals(childs.item(0).getLocalName(), "EncryptedKey");
        Assert.assertEquals(childs.item(1).getLocalName(), "EncryptedData");

        attachmentCallbackHandler = new AttachmentCallbackHandler(encryptedAttachments);
        verify(doc, attachmentCallbackHandler);

        Assert.assertFalse(attachmentCallbackHandler.getResponseAttachments().isEmpty());
        Attachment responseAttachment = attachmentCallbackHandler.getResponseAttachments().get(0);

        byte[] attachmentBytes = readInputStream(responseAttachment.getSourceStream());
        Assert.assertTrue(Arrays.equals(attachmentBytes, SOAPUtil.SAMPLE_SOAP_MSG.getBytes(StandardCharsets.UTF_8)));
        Assert.assertEquals("text/xml", responseAttachment.getMimeType());

        Map<String, String> attHeaders = responseAttachment.getHeaders();
        Assert.assertEquals(6, attHeaders.size());
    }

    @org.junit.Test
    public void testXMLAttachmentCompleteEncryption() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecEncrypt encrypt = new WSSecEncrypt();
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        encrypt.getParts().add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Content"));
        encrypt.getParts().add(new WSEncryptionPart("cid:Attachments", "Element"));

        String attachmentId = UUID.randomUUID().toString();
        final Attachment attachment = new Attachment();
        attachment.setMimeType("text/xml");
        attachment.addHeaders(getHeaders(attachmentId));
        attachment.setId(attachmentId);
        attachment.setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes(StandardCharsets.UTF_8)));

        AttachmentCallbackHandler attachmentCallbackHandler =
            new AttachmentCallbackHandler(Collections.singletonList(attachment));
        encrypt.setAttachmentCallbackHandler(attachmentCallbackHandler);
        List<Attachment> encryptedAttachments = attachmentCallbackHandler.getResponseAttachments();

        Document encryptedDoc = encrypt.build(doc, crypto, secHeader);

        Assert.assertEquals(1, encryptedAttachments.get(0).getHeaders().size());

        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.PrettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }

        attachmentCallbackHandler = new AttachmentCallbackHandler(encryptedAttachments);
        verify(encryptedDoc, attachmentCallbackHandler);

        Assert.assertFalse(attachmentCallbackHandler.getResponseAttachments().isEmpty());
        Attachment responseAttachment = attachmentCallbackHandler.getResponseAttachments().get(0);

        byte[] attachmentBytes = readInputStream(responseAttachment.getSourceStream());
        Assert.assertTrue(Arrays.equals(attachmentBytes, SOAPUtil.SAMPLE_SOAP_MSG.getBytes(StandardCharsets.UTF_8)));
        Assert.assertEquals("text/xml", responseAttachment.getMimeType());

        Map<String, String> attHeaders = responseAttachment.getHeaders();
        Assert.assertEquals(6, attHeaders.size());
    }

    @org.junit.Test
    public void testInvalidXMLAttachmentCompleteEncryption() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecEncrypt encrypt = new WSSecEncrypt();
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        encrypt.getParts().add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Content"));
        encrypt.getParts().add(new WSEncryptionPart("cid:Attachments", "Element"));

        String attachmentId = UUID.randomUUID().toString();
        final Attachment attachment = new Attachment();
        attachment.setMimeType("text/xml");
        attachment.addHeaders(getHeaders(attachmentId));
        attachment.setId(attachmentId);
        attachment.setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes(StandardCharsets.UTF_8)));

        AttachmentCallbackHandler attachmentCallbackHandler =
            new AttachmentCallbackHandler(Collections.singletonList(attachment));
        encrypt.setAttachmentCallbackHandler(attachmentCallbackHandler);
        List<Attachment> encryptedAttachments = attachmentCallbackHandler.getResponseAttachments();

        Document encryptedDoc = encrypt.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.PrettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }

        try {
            final PushbackInputStream pis =
                new PushbackInputStream(encryptedAttachments.get(0).getSourceStream(), 1);
            pis.unread('K');
            encryptedAttachments.get(0).setSourceStream(pis);

            attachmentCallbackHandler = new AttachmentCallbackHandler(encryptedAttachments);
            verify(encryptedDoc, attachmentCallbackHandler);
        } catch (WSSecurityException e) {
            // Assert.assertEquals(e.getMessage(), "The signature or decryption was invalid");
            return;
        }

        Assert.assertFalse(attachmentCallbackHandler.getResponseAttachments().isEmpty());
        Attachment responseAttachment = attachmentCallbackHandler.getResponseAttachments().get(0);
        byte[] attachmentBytes = readInputStream(responseAttachment.getSourceStream());
        Assert.assertFalse(Arrays.equals(attachmentBytes, SOAPUtil.SAMPLE_SOAP_MSG.getBytes(StandardCharsets.UTF_8)));
        Assert.assertEquals("text/xml", responseAttachment.getMimeType());
    }

    @org.junit.Test
    public void testMultipleAttachmentCompleteEncryption() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecEncrypt encrypt = new WSSecEncrypt();
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        encrypt.getParts().add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Content"));
        encrypt.getParts().add(new WSEncryptionPart("cid:Attachments", "Element"));

        final String attachment1Id = UUID.randomUUID().toString();
        final Attachment[] attachment = new Attachment[2];
        attachment[0] = new Attachment();
        attachment[0].setMimeType("text/xml");
        attachment[0].addHeaders(getHeaders(attachment1Id));
        attachment[0].setId(attachment1Id);
        attachment[0].setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes(StandardCharsets.UTF_8)));

        final String attachment2Id = UUID.randomUUID().toString();
        attachment[1] = new Attachment();
        attachment[1].setMimeType("text/plain");
        attachment[1].addHeaders(getHeaders(attachment2Id));
        attachment[1].setId(attachment2Id);
        attachment[1].setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes(StandardCharsets.UTF_8)));

        AttachmentCallbackHandler attachmentCallbackHandler =
            new AttachmentCallbackHandler(Arrays.asList(attachment));
        encrypt.setAttachmentCallbackHandler(attachmentCallbackHandler);
        List<Attachment> encryptedAttachments = attachmentCallbackHandler.getResponseAttachments();

        Document encryptedDoc = encrypt.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.PrettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }

        attachmentCallbackHandler = new AttachmentCallbackHandler(encryptedAttachments);
        verify(encryptedDoc, attachmentCallbackHandler);

        Assert.assertFalse(attachmentCallbackHandler.getResponseAttachments().isEmpty());
        Attachment responseAttachment = attachmentCallbackHandler.getResponseAttachments().get(0);

        byte[] attachment1Bytes = readInputStream(responseAttachment.getSourceStream());
        Assert.assertTrue(Arrays.equals(attachment1Bytes, SOAPUtil.SAMPLE_SOAP_MSG.getBytes(StandardCharsets.UTF_8)));
        Assert.assertEquals("text/xml", responseAttachment.getMimeType());
        Map<String, String> att1Headers = responseAttachment.getHeaders();
        Assert.assertEquals(6, att1Headers.size());

        responseAttachment = attachmentCallbackHandler.getResponseAttachments().get(1);
        byte[] attachment2Bytes = readInputStream(responseAttachment.getSourceStream());
        Assert.assertTrue(Arrays.equals(attachment2Bytes, SOAPUtil.SAMPLE_SOAP_MSG.getBytes(StandardCharsets.UTF_8)));
        Assert.assertEquals("text/plain", responseAttachment.getMimeType());

        Map<String, String> att2Headers = responseAttachment.getHeaders();
        Assert.assertEquals(6, att2Headers.size());
    }

    @org.junit.Test
    public void testXMLAttachmentCmplSignCmplEnc() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecSignature signature = new WSSecSignature();
        signature.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");

        signature.getParts().add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Content"));
        signature.getParts().add(new WSEncryptionPart("cid:Attachments", "Element"));

        String attachmentId = UUID.randomUUID().toString();
        final Attachment attachment = new Attachment();
        attachment.setMimeType("text/xml");
        attachment.addHeaders(getHeaders(attachmentId));
        attachment.setId(attachmentId);
        attachment.setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes(StandardCharsets.UTF_8)));

        AttachmentCallbackHandler attachmentCallbackHandler =
            new AttachmentCallbackHandler(Collections.singletonList(attachment));
        signature.setAttachmentCallbackHandler(attachmentCallbackHandler);

        doc = signature.build(doc, crypto, secHeader);

        WSSecEncrypt encrypt = new WSSecEncrypt();
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        encrypt.getParts().addAll(signature.getParts());

        attachmentCallbackHandler =
            new AttachmentCallbackHandler(Collections.singletonList(attachment));
        encrypt.setAttachmentCallbackHandler(attachmentCallbackHandler);
        List<Attachment> encryptedAttachments = attachmentCallbackHandler.getResponseAttachments();

        Document encryptedDoc = encrypt.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.PrettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }

        NodeList securityHeaderElement = doc.getElementsByTagNameNS(WSConstants.WSSE_NS, "Security");
        Assert.assertEquals(1, securityHeaderElement.getLength());
        NodeList childs = securityHeaderElement.item(0).getChildNodes();
        Assert.assertEquals(3, childs.getLength());
        Assert.assertEquals(childs.item(0).getLocalName(), "EncryptedKey");
        Assert.assertEquals(childs.item(1).getLocalName(), "EncryptedData");
        Assert.assertEquals(childs.item(2).getLocalName(), "Signature");

        attachmentCallbackHandler = new AttachmentCallbackHandler(encryptedAttachments);
        verify(encryptedDoc, attachmentCallbackHandler);

        Assert.assertFalse(attachmentCallbackHandler.getResponseAttachments().isEmpty());
        Attachment responseAttachment = attachmentCallbackHandler.getResponseAttachments().get(1);

        byte[] attachmentBytes = readInputStream(responseAttachment.getSourceStream());
        Assert.assertTrue(Arrays.equals(attachmentBytes, SOAPUtil.SAMPLE_SOAP_MSG.getBytes(StandardCharsets.UTF_8)));
        Assert.assertEquals("text/xml", responseAttachment.getMimeType());

        Map<String, String> attHeaders = responseAttachment.getHeaders();
        Assert.assertEquals(6, attHeaders.size());
    }

    @org.junit.Test
    public void testInvalidXMLAttachmentCmplSignCmplEnc() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecSignature signature = new WSSecSignature();
        signature.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");

        signature.getParts().add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Content"));
        signature.getParts().add(new WSEncryptionPart("cid:Attachments", "Element"));

        String attachmentId = UUID.randomUUID().toString();
        final Attachment[] attachment = new Attachment[1];
        attachment[0] = new Attachment();
        attachment[0].setMimeType("text/xml");
        attachment[0].addHeaders(getHeaders(attachmentId));
        attachment[0].setId(attachmentId);
        attachment[0].setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes(StandardCharsets.UTF_8)));

        signature.setAttachmentCallbackHandler(new CallbackHandler() {
            @Override
            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                if (callbacks[0] instanceof AttachmentRequestCallback) {
                    AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callbacks[0];

                    List<Attachment> attachments = new ArrayList<>();
                    attachments.add(attachment[0]);
                    attachmentRequestCallback.setAttachments(attachments);
                } else {
                    AttachmentResultCallback attachmentResultCallback = (AttachmentResultCallback) callbacks[0];
                    attachment[0] = attachmentResultCallback.getAttachment();
                }
            }
        });

        doc = signature.build(doc, crypto, secHeader);

        WSSecEncrypt encrypt = new WSSecEncrypt();
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        encrypt.getParts().addAll(signature.getParts());

        encrypt.setAttachmentCallbackHandler(new CallbackHandler() {
            @Override
            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                if (callbacks[0] instanceof AttachmentRequestCallback) {
                    AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callbacks[0];

                    List<Attachment> attachments = new ArrayList<>();
                    attachments.add(attachment[0]);
                    attachmentRequestCallback.setAttachments(attachments);
                } else {
                    AttachmentResultCallback attachmentResultCallback = (AttachmentResultCallback) callbacks[0];
                    attachment[0] = attachmentResultCallback.getAttachment();
                }
            }
        });

        Document encryptedDoc = encrypt.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.PrettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }

        try {
            verify(encryptedDoc, new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof AttachmentRequestCallback) {
                        AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callbacks[0];

                        if (!attachment[0].getId().equals(attachmentRequestCallback.getAttachmentId())) {
                            throw new RuntimeException("wrong attachment requested");
                        }

                        List<Attachment> attachments = new ArrayList<>();
                        attachments.add(attachment[0]);

                        if (attachment[0].getHeaders().size() == 6) {
                            //signature callback
                            attachment[0].addHeader(AttachmentUtils.MIME_HEADER_CONTENT_DESCRIPTION, "Kaputt");
                        }

                        attachmentRequestCallback.setAttachments(attachments);
                    } else {
                        AttachmentResultCallback attachmentResultCallback = (AttachmentResultCallback) callbacks[0];
                        attachment[0] = attachmentResultCallback.getAttachment();
                    }
                }
            });
            Assert.fail();
        } catch (WSSecurityException e) {
            Assert.assertEquals(e.getMessage(), "The signature or decryption was invalid");
        }
    }

    @org.junit.Test
    public void testXMLAttachmentCmplEncCmplSign() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecEncrypt encrypt = new WSSecEncrypt();
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        encrypt.getParts().add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Content"));
        encrypt.getParts().add(new WSEncryptionPart("cid:Attachments", "Element"));

        String attachmentId = UUID.randomUUID().toString();
        final Attachment attachment = new Attachment();
        attachment.setMimeType("text/xml");
        attachment.addHeaders(getHeaders(attachmentId));
        attachment.setId(attachmentId);
        attachment.setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes(StandardCharsets.UTF_8)));

        AttachmentCallbackHandler attachmentCallbackHandler =
            new AttachmentCallbackHandler(Collections.singletonList(attachment));
        encrypt.setAttachmentCallbackHandler(attachmentCallbackHandler);
        List<Attachment> encryptedAttachments = attachmentCallbackHandler.getResponseAttachments();

        doc = encrypt.build(doc, crypto, secHeader);

        WSSecSignature signature = new WSSecSignature();
        signature.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        signature.getParts().addAll(encrypt.getParts());

        attachmentCallbackHandler = new AttachmentCallbackHandler(encryptedAttachments);
        signature.setAttachmentCallbackHandler(attachmentCallbackHandler);
        encryptedAttachments = attachmentCallbackHandler.getResponseAttachments();

        doc = signature.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        NodeList securityHeaderElement = doc.getElementsByTagNameNS(WSConstants.WSSE_NS, "Security");
        Assert.assertEquals(1, securityHeaderElement.getLength());
        NodeList childs = securityHeaderElement.item(0).getChildNodes();
        Assert.assertEquals(3, childs.getLength());
        Assert.assertEquals(childs.item(0).getLocalName(), "Signature");
        Assert.assertEquals(childs.item(1).getLocalName(), "EncryptedKey");
        Assert.assertEquals(childs.item(2).getLocalName(), "EncryptedData");

        attachmentCallbackHandler = new AttachmentCallbackHandler(encryptedAttachments);
        verify(doc, attachmentCallbackHandler);

        Assert.assertFalse(attachmentCallbackHandler.getResponseAttachments().isEmpty());
        Attachment responseAttachment = attachmentCallbackHandler.getResponseAttachments().get(1);

        byte[] attachmentBytes = readInputStream(responseAttachment.getSourceStream());
        Assert.assertTrue(Arrays.equals(attachmentBytes, SOAPUtil.SAMPLE_SOAP_MSG.getBytes(StandardCharsets.UTF_8)));
        Assert.assertEquals("text/xml", responseAttachment.getMimeType());

        Map<String, String> attHeaders = responseAttachment.getHeaders();
        Assert.assertEquals(6, attHeaders.size());
    }

    @org.junit.Test
    public void testInvalidXMLAttachmentCmplEncCmplSign() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecEncrypt encrypt = new WSSecEncrypt();
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        encrypt.getParts().add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Content"));
        encrypt.getParts().add(new WSEncryptionPart("cid:Attachments", "Element"));

        String attachmentId = UUID.randomUUID().toString();
        final Attachment[] attachment = new Attachment[1];
        attachment[0] = new Attachment();
        attachment[0].setMimeType("text/xml");
        attachment[0].addHeaders(getHeaders(attachmentId));
        attachment[0].setId(attachmentId);
        attachment[0].setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes(StandardCharsets.UTF_8)));

        encrypt.setAttachmentCallbackHandler(new CallbackHandler() {
            @Override
            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                if (callbacks[0] instanceof AttachmentRequestCallback) {
                    AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callbacks[0];

                    List<Attachment> attachments = new ArrayList<>();
                    attachments.add(attachment[0]);
                    attachmentRequestCallback.setAttachments(attachments);
                } else {
                    AttachmentResultCallback attachmentResultCallback = (AttachmentResultCallback) callbacks[0];
                    attachment[0] = attachmentResultCallback.getAttachment();
                }
            }
        });

        doc = encrypt.build(doc, crypto, secHeader);

        WSSecSignature signature = new WSSecSignature();
        signature.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        signature.getParts().addAll(encrypt.getParts());

        signature.setAttachmentCallbackHandler(new CallbackHandler() {
            @Override
            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                if (callbacks[0] instanceof AttachmentRequestCallback) {
                    AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callbacks[0];

                    List<Attachment> attachments = new ArrayList<>();
                    attachments.add(attachment[0]);
                    attachmentRequestCallback.setAttachments(attachments);
                } else {
                    AttachmentResultCallback attachmentResultCallback = (AttachmentResultCallback) callbacks[0];
                    attachment[0] = attachmentResultCallback.getAttachment();
                }
            }
        });

        doc = signature.build(doc, crypto, secHeader);

        if (LOG.isDebugEnabled()) {
            String outputString = XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        final PushbackInputStream pis = new PushbackInputStream(attachment[0].getSourceStream(), 1);
        pis.unread('K');
        attachment[0].setSourceStream(pis);
        try {
            verify(doc, new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof AttachmentRequestCallback) {
                        AttachmentRequestCallback attachmentRequestCallback = (AttachmentRequestCallback) callbacks[0];

                        if (!attachment[0].getId().equals(attachmentRequestCallback.getAttachmentId())) {
                            throw new RuntimeException("wrong attachment requested");
                        }

                        List<Attachment> attachmentList = new ArrayList<>();
                        attachmentList.add(attachment[0]);
                        attachmentRequestCallback.setAttachments(attachmentList);

                    } else {
                        AttachmentResultCallback attachmentResultCallback = (AttachmentResultCallback) callbacks[0];
                        attachment[0] = attachmentResultCallback.getAttachment();
                    }
                }
            });
            Assert.fail();
        } catch (WSSecurityException e) {
            Assert.assertEquals(e.getMessage(), "The signature or decryption was invalid");
        }
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
