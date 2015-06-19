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
package org.apache.wss4j.stax.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Properties;
import java.util.UUID;

import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.WSS4JConstants;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.Merlin;
import org.apache.wss4j.common.ext.Attachment;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.common.SOAPUtil;
import org.apache.wss4j.dom.message.AttachmentCallbackHandler;
import org.apache.wss4j.dom.message.WSSecEncrypt;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.apache.wss4j.stax.WSSec;
import org.apache.wss4j.stax.ext.InboundWSSec;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.test.utils.StAX2DOM;
import org.junit.Assert;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Test for processing an xop:Include inside a CipherValue Element
 * TODO Not supported yet.
 */
@org.junit.Ignore
public class XOPAttachmentTest extends AbstractTestBase {

    public XOPAttachmentTest() throws Exception {
    }

    protected byte[] readInputStream(InputStream inputStream) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        int read = 0;
        byte[] buf = new byte[4096];
        while ((read = inputStream.read(buf)) != -1) {
            byteArrayOutputStream.write(buf, 0, read);
        }
        return byteArrayOutputStream.toByteArray();
    }

    // Set up a test to encrypt the SOAP Body + an attachment, which is the same content as 
    // the SOAP Body. Then replace the encrypted SOAP Body with a xop:Include to the attachment,
    // and modify the request to remove the encryption stuff pointing to the attachment.
    @org.junit.Test
    public void testEncryptedSOAPBody() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        List<Attachment> attachments = createEncryptedBodyInAttachment(doc);
        // System.out.println("DOC: " + DOM2Writer.nodeToString(doc));
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
        transformer.transform(new DOMSource(doc), new StreamResult(baos));
        
        //done signature; now test sig-verification:
        AttachmentCallbackHandler attachmentCallbackHandler = new AttachmentCallbackHandler(attachments);
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandlerImpl());
            securityProperties.setAttachmentCallbackHandler(attachmentCallbackHandler);

            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));
            Document document = StAX2DOM.readDoc(documentBuilderFactory.newDocumentBuilder(), xmlStreamReader);

            NodeList sigReferences = document.getElementsByTagNameNS(WSConstants.SIG_NS, "Reference");
            Assert.assertEquals(2, sigReferences.getLength());
        }
        Assert.assertFalse(attachmentCallbackHandler.getResponseAttachments().isEmpty());
        Attachment responseAttachment = attachmentCallbackHandler.getResponseAttachments().get(0);
        
        byte[] attachmentBytes = readInputStream(responseAttachment.getSourceStream());
        Assert.assertTrue(Arrays.equals(attachmentBytes, SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));
        Assert.assertEquals("text/xml", responseAttachment.getMimeType());
    }
    
    private List<Attachment> createEncryptedBodyInAttachment(Document doc) throws Exception {
        WSSecEncrypt encrypt = new WSSecEncrypt();
        encrypt.setUserInfo("receiver", "default");
        encrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        encrypt.getParts().add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Content"));
        encrypt.getParts().add(new WSEncryptionPart("cid:Attachments", "Content"));

        String attachmentId = UUID.randomUUID().toString();
        final Attachment attachment = new Attachment();
        attachment.setId(attachmentId);
        attachment.setSourceStream(new ByteArrayInputStream(SOAPUtil.SAMPLE_SOAP_MSG.getBytes("UTF-8")));

        AttachmentCallbackHandler attachmentCallbackHandler = 
            new AttachmentCallbackHandler(Collections.singletonList(attachment));
        encrypt.setAttachmentCallbackHandler(attachmentCallbackHandler);
        List<Attachment> encryptedAttachments = attachmentCallbackHandler.getResponseAttachments();

        Properties sigProperties = new Properties();
        sigProperties.setProperty("org.apache.wss4j.crypto.provider", "org.apache.wss4j.common.crypto.Merlin");
        sigProperties.setProperty("org.apache.wss4j.crypto.merlin.keystore.file", "transmitter.jks");
        sigProperties.setProperty("org.apache.wss4j.crypto.merlin.keystore.password", "default");
        Crypto crypto = new Merlin(sigProperties, this.getClass().getClassLoader(), null);
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
        
        return encryptedAttachments;
    }
    
}
