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
import org.apache.wss4j.dom.WSSConfig;
import org.apache.wss4j.dom.WSSecurityEngine;
import org.apache.wss4j.dom.common.KeystoreCallbackHandler;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * Test for processing an xop:Include inside a CipherValue Element
 */
public class XOPAttachmentTest extends org.junit.Assert {

    private static final String SOAP_BODY = 
        "<add xmlns=\"http://ws.apache.org/counter/counter_port_type\">" 
        + "<value xmlns=\"\">15</value>" 
        + "</add>";
    
    private static final org.slf4j.Logger LOG =
            org.slf4j.LoggerFactory.getLogger(XOPAttachmentTest.class);

    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private Crypto crypto = null;

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
    @org.junit.Test
    public void testEncryptedSOAPBody() throws Exception {
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
            String outputString = XMLUtils.PrettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
            //System.out.println(outputString);
        }

        attachmentCallbackHandler = new AttachmentCallbackHandler(encryptedAttachments);
        verify(encryptedDoc, attachmentCallbackHandler);
        
        String processedDoc = XMLUtils.PrettyDocumentToString(encryptedDoc);
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
