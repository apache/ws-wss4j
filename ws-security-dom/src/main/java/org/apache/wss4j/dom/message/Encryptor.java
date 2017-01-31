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

import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;

import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.ext.Attachment;
import org.apache.wss4j.common.ext.AttachmentRequestCallback;
import org.apache.wss4j.common.ext.AttachmentResultCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.AttachmentUtils;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WsuIdAllocator;
import org.apache.wss4j.dom.callback.CallbackLookup;
import org.apache.wss4j.dom.callback.DOMCallbackLookup;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.encryption.AbstractSerializer;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.Serializer;
import org.apache.xml.security.encryption.TransformSerializer;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLCipherUtil;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.utils.EncryptionConstants;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * A class to encrypt references.
 */
public class Encryptor {
    
    private Document doc;
    private WSSecHeader securityHeader;
    private WsuIdAllocator idAllocator;
    private CallbackLookup callbackLookup;
    private CallbackHandler attachmentCallbackHandler;
    private boolean storeBytesInAttachment;
    private Serializer encryptionSerializer;

    public List<String> doEncryption(
        KeyInfo keyInfo,
        SecretKey secretKey,
        String encryptionAlgorithm,
        List<WSEncryptionPart> references,
        List<Element> attachmentEncryptedDataElements
    ) throws WSSecurityException {

        XMLCipher xmlCipher = null;
        try {
            xmlCipher = XMLCipher.getInstance(encryptionAlgorithm);
        } catch (XMLEncryptionException ex) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.UNSUPPORTED_ALGORITHM, ex
            );
        }
        if (encryptionSerializer != null) {
            xmlCipher.setSerializer(encryptionSerializer);
        }

        List<String> encDataRef = new ArrayList<>();
        WSEncryptionPart attachmentEncryptionPart = null;
        for (int part = 0; part < references.size(); part++) {
            WSEncryptionPart encPart = references.get(part);

            if (encPart.getId() != null && encPart.getId().startsWith("cid:")) {
                attachmentEncryptionPart = encPart;
                continue;
            }

            //
            // Get the data to encrypt.
            //
            if (callbackLookup == null) {
                callbackLookup = new DOMCallbackLookup(doc);
            }
            List<Element> elementsToEncrypt =
                WSSecurityUtil.findElements(encPart, callbackLookup, doc);
            if (elementsToEncrypt == null || elementsToEncrypt.size() == 0) {
                if (!encPart.isRequired()) {
                    continue;
                }
                throw new WSSecurityException(
                    WSSecurityException.ErrorCode.FAILURE,
                    "noEncElement",
                    new Object[] {"{" + encPart.getNamespace() + "}" + encPart.getName()});
            }

            if (storeBytesInAttachment) {
                for (Element elementToEncrypt : elementsToEncrypt) {
                    try {
                        String id =
                            encryptElementInAttachment(keyInfo, secretKey, encryptionAlgorithm, encPart, elementToEncrypt);
                        encPart.setEncId(id);
                        encDataRef.add("#" + id);
                    } catch (Exception ex) {
                        throw new WSSecurityException(
                            WSSecurityException.ErrorCode.FAILED_ENCRYPTION, ex
                        );
                    }
                }
            } else {
                for (Element elementToEncrypt : elementsToEncrypt) {
                    String id =
                        encryptElement(elementToEncrypt, encPart.getEncModifier(), xmlCipher, secretKey, keyInfo);
                    encPart.setEncId(id);
                    encDataRef.add("#" + id);
                }
            }
        }

        if (attachmentEncryptionPart != null) {
            encryptAttachment(keyInfo, secretKey, encryptionAlgorithm, attachmentEncryptionPart, encDataRef,
                              attachmentEncryptedDataElements);
        }

        return encDataRef;
    }

    private String encryptElementInAttachment(
        KeyInfo keyInfo,
        SecretKey secretKey,
        String encryptionAlgorithm,
        WSEncryptionPart encryptionPart,
        Element elementToEncrypt
   ) throws Exception {

        String type = EncryptionConstants.TYPE_ELEMENT;
        if ("Content".equals(encryptionPart.getEncModifier())) {
            type = EncryptionConstants.TYPE_CONTENT;
        }

        final String attachmentId = idAllocator.createId("", doc);
        String encEncryptedDataId = idAllocator.createId("ED-", attachmentId);

        if ("Header".equals(encryptionPart.getEncModifier())
            && elementToEncrypt.getParentNode().equals(WSSecurityUtil.getSOAPHeader(doc))) {
            createEncryptedHeaderElement(doc, securityHeader, elementToEncrypt, idAllocator);
        }

        Element encryptedData =
            doc.createElementNS(WSConstants.ENC_NS, WSConstants.ENC_PREFIX + ":EncryptedData");
        encryptedData.setAttributeNS(null, "Id", encEncryptedDataId);
        encryptedData.setAttributeNS(null, "Type", type);

        Element encryptionMethod =
            doc.createElementNS(WSConstants.ENC_NS, WSConstants.ENC_PREFIX + ":EncryptionMethod");
        encryptionMethod.setAttributeNS(null, "Algorithm", encryptionAlgorithm);

        encryptedData.appendChild(encryptionMethod);
        encryptedData.appendChild(keyInfo.getElement().cloneNode(true));

        Element cipherData =
            doc.createElementNS(WSConstants.ENC_NS, WSConstants.ENC_PREFIX + ":CipherData");
        Element cipherValue =
            doc.createElementNS(WSConstants.ENC_NS, WSConstants.ENC_PREFIX + ":CipherValue");
        cipherData.appendChild(cipherValue);
        encryptedData.appendChild(cipherData);

        Cipher cipher = createCipher(encryptionAlgorithm, secretKey);

        // Serialize and encrypt the element
        AbstractSerializer serializer = new TransformSerializer();
        serializer.setCanonicalizer(Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_PHYSICAL));
        serializer.setSecureValidation(true);

        byte[] serializedOctets = null;
        if (type.equals(EncryptionConstants.TYPE_CONTENT)) {
            NodeList children = elementToEncrypt.getChildNodes();
            if (null != children) {
                serializedOctets = serializer.serializeToByteArray(children);
            } else {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_ENCRYPTION, 
                                              "Element has no content.");
            }
        } else {
            serializedOctets = serializer.serializeToByteArray(elementToEncrypt);
        }

        byte[] encryptedBytes = null;
        try {
            encryptedBytes = cipher.doFinal(serializedOctets);
        } catch (IllegalBlockSizeException ibse) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_ENCRYPTION, ibse);
        } catch (BadPaddingException bpe) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_ENCRYPTION, bpe);
        }

        // Now build up to a properly XML Encryption encoded octet stream
        byte[] iv = cipher.getIV();
        byte[] finalEncryptedBytes = new byte[iv.length + encryptedBytes.length];
        System.arraycopy(iv, 0, finalEncryptedBytes, 0, iv.length);
        System.arraycopy(encryptedBytes, 0, finalEncryptedBytes, iv.length, encryptedBytes.length);

        if ("Content".equals(encryptionPart.getEncModifier())) {
            Node child = elementToEncrypt.getFirstChild();
            while (child != null) {
                Node sibling = child.getNextSibling();
                elementToEncrypt.removeChild(child);
                child = sibling;
            }
            elementToEncrypt.appendChild(encryptedData);
        } else {
            elementToEncrypt.getParentNode().replaceChild(encryptedData, elementToEncrypt);
        }

        WSSecurityUtil.storeBytesInAttachment(cipherValue, doc, attachmentId,
                                              finalEncryptedBytes, attachmentCallbackHandler);

        return encEncryptedDataId;
    }

    private void encryptAttachment(
        KeyInfo keyInfo,
        SecretKey secretKey,
        String encryptionAlgorithm,
        WSEncryptionPart attachmentEncryptionPart,
        List<String> encDataRef,
        List<Element> attachmentEncryptedDataElements
    ) throws WSSecurityException {
        if (attachmentCallbackHandler == null) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.FAILURE,
                "empty", new Object[] {"no attachment callbackhandler supplied"}
            );
        }

        AttachmentRequestCallback attachmentRequestCallback = new AttachmentRequestCallback();
        String id = attachmentEncryptionPart.getId().substring(4);
        attachmentRequestCallback.setAttachmentId(id);
        try {
            attachmentCallbackHandler.handle(new Callback[]{attachmentRequestCallback});
        } catch (Exception e) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.FAILED_ENCRYPTION, e
            );
        }
        String attachmentEncryptedDataType = WSConstants.SWA_ATTACHMENT_ENCRYPTED_DATA_TYPE_CONTENT_ONLY;
        if ("Element".equals(attachmentEncryptionPart.getEncModifier())) {
            attachmentEncryptedDataType = WSConstants.SWA_ATTACHMENT_ENCRYPTED_DATA_TYPE_COMPLETE;
        }

        for (Attachment attachment : attachmentRequestCallback.getAttachments()) {

            final String attachmentId = attachment.getId();
            String encEncryptedDataId = idAllocator.createId("ED-", attachmentId);
            encDataRef.add("#" + encEncryptedDataId);

            Element encryptedData =
                doc.createElementNS(WSConstants.ENC_NS, WSConstants.ENC_PREFIX + ":EncryptedData");
            encryptedData.setAttributeNS(null, "Id", encEncryptedDataId);
            encryptedData.setAttributeNS(null, "MimeType", attachment.getMimeType());
            encryptedData.setAttributeNS(null, "Type", attachmentEncryptedDataType);

            Element encryptionMethod =
                doc.createElementNS(WSConstants.ENC_NS, WSConstants.ENC_PREFIX + ":EncryptionMethod");
            encryptionMethod.setAttributeNS(null, "Algorithm", encryptionAlgorithm);

            encryptedData.appendChild(encryptionMethod);
            encryptedData.appendChild(keyInfo.getElement().cloneNode(true));

            Element cipherData =
                doc.createElementNS(WSConstants.ENC_NS, WSConstants.ENC_PREFIX + ":CipherData");
            Element cipherReference =
                doc.createElementNS(WSConstants.ENC_NS, WSConstants.ENC_PREFIX + ":CipherReference");
            cipherReference.setAttributeNS(null, "URI", "cid:" + attachmentId);

            Element transforms = doc.createElementNS(WSConstants.ENC_NS, WSConstants.ENC_PREFIX + ":Transforms");
            Element transform = doc.createElementNS(WSConstants.SIG_NS, WSConstants.SIG_PREFIX + ":Transform");
            transform.setAttributeNS(null, "Algorithm", WSConstants.SWA_ATTACHMENT_CIPHERTEXT_TRANS);
            transforms.appendChild(transform);

            cipherReference.appendChild(transforms);
            cipherData.appendChild(cipherReference);
            encryptedData.appendChild(cipherData);

            attachmentEncryptedDataElements.add(encryptedData);

            Attachment resultAttachment = new Attachment();
            resultAttachment.setId(attachmentId);
            resultAttachment.setMimeType("application/octet-stream");

            Cipher cipher = createCipher(encryptionAlgorithm, secretKey);

            Map<String, String> headers = new HashMap<>(attachment.getHeaders());
            resultAttachment.setSourceStream(
                AttachmentUtils.setupAttachmentEncryptionStream(
                    cipher, "Element".equals(attachmentEncryptionPart.getEncModifier()),
                    attachment, headers
                )
            );
            resultAttachment.addHeaders(headers);

            AttachmentResultCallback attachmentResultCallback = new AttachmentResultCallback();
            attachmentResultCallback.setAttachmentId(attachmentId);
            attachmentResultCallback.setAttachment(resultAttachment);
            try {
                attachmentCallbackHandler.handle(new Callback[]{attachmentResultCallback});
            } catch (Exception e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_ENCRYPTION, e);
            }
        }
    }

    private Cipher createCipher(String encryptionAlgorithm, SecretKey secretKey)
        throws WSSecurityException {
        String jceAlgorithm = JCEMapper.translateURItoJCEID(encryptionAlgorithm);
        try {
            Cipher cipher = Cipher.getInstance(jceAlgorithm);
            
            int ivLen = JCEMapper.getIVLengthFromURI(encryptionAlgorithm) / 8;
            byte[] iv = XMLSecurityConstants.generateBytes(ivLen);
            AlgorithmParameterSpec paramSpec = 
                XMLCipherUtil.constructBlockCipherParameters(encryptionAlgorithm, iv, Encryptor.class);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec);

            return cipher;
        } catch (Exception e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_ENCRYPTION, e);
        }
    }

    /**
     * Encrypt an element.
     */
    private String encryptElement(
        Element elementToEncrypt,
        String modifier,
        XMLCipher xmlCipher,
        SecretKey secretKey,
        KeyInfo keyInfo
    ) throws WSSecurityException {

        boolean content = "Content".equals(modifier);
        //
        // Encrypt data, and set necessary attributes in xenc:EncryptedData
        //
        String xencEncryptedDataId = idAllocator.createId("ED-", elementToEncrypt);
        try {
            if ("Header".equals(modifier)
                && elementToEncrypt.getParentNode().equals(WSSecurityUtil.getSOAPHeader(doc))) {
                createEncryptedHeaderElement(doc, securityHeader, elementToEncrypt, idAllocator);
            }

            xmlCipher.init(XMLCipher.ENCRYPT_MODE, secretKey);
            EncryptedData encData = xmlCipher.getEncryptedData();
            encData.setId(xencEncryptedDataId);
            encData.setKeyInfo(keyInfo);
            xmlCipher.doFinal(doc, elementToEncrypt, content);
            return xencEncryptedDataId;
        } catch (Exception ex) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.FAILED_ENCRYPTION, ex
            );
        }
    }

    private static void createEncryptedHeaderElement(
        Document doc,
        WSSecHeader securityHeader,
        Element elementToEncrypt,
        WsuIdAllocator idAllocator
    ) {
        Element elem =
            doc.createElementNS(
                WSConstants.WSSE11_NS, "wsse11:" + WSConstants.ENCRYPTED_HEADER
            );
        XMLUtils.setNamespace(elem, WSConstants.WSSE11_NS, WSConstants.WSSE11_PREFIX);
        String wsuPrefix =
            XMLUtils.setNamespace(elem, WSConstants.WSU_NS, WSConstants.WSU_PREFIX);
        String headerId = idAllocator.createId("EH-", elementToEncrypt);
        elem.setAttributeNS(
            WSConstants.WSU_NS, wsuPrefix + ":Id", headerId
        );

        //
        // Add the EncryptedHeader node to the element to be encrypted's parent
        // (i.e. the SOAP header). Add the element to be encrypted to the Encrypted
        // Header node as well
        //
        Node parent = elementToEncrypt.getParentNode();
        elementToEncrypt = (Element)parent.replaceChild(elem, elementToEncrypt);
        elem.appendChild(elementToEncrypt);

        if (securityHeader != null) {
            NamedNodeMap map = securityHeader.getSecurityHeaderElement().getAttributes();
            for (int i = 0; i < map.getLength(); i++) {
                Attr attr = (Attr)map.item(i);
                if (WSConstants.URI_SOAP11_ENV.equals(attr.getNamespaceURI())
                    || WSConstants.URI_SOAP12_ENV.equals(attr.getNamespaceURI())) {
                    String soapEnvPrefix =
                        XMLUtils.setNamespace(
                            elem, attr.getNamespaceURI(), WSConstants.DEFAULT_SOAP_PREFIX
                        );
                    elem.setAttributeNS(
                        attr.getNamespaceURI(),
                        soapEnvPrefix + ":" + attr.getLocalName(),
                        attr.getValue()
                    );
                }
            }
        }

    }

    public Document getDoc() {
        return doc;
    }

    public void setDoc(Document doc) {
        this.doc = doc;
    }

    public WSSecHeader getSecurityHeader() {
        return securityHeader;
    }

    public void setSecurityHeader(WSSecHeader securityHeader) {
        this.securityHeader = securityHeader;
    }

    public WsuIdAllocator getIdAllocator() {
        return idAllocator;
    }

    public void setIdAllocator(WsuIdAllocator idAllocator) {
        this.idAllocator = idAllocator;
    }

    public CallbackLookup getCallbackLookup() {
        return callbackLookup;
    }

    public void setCallbackLookup(CallbackLookup callbackLookup) {
        this.callbackLookup = callbackLookup;
    }

    public CallbackHandler getAttachmentCallbackHandler() {
        return attachmentCallbackHandler;
    }

    public void setAttachmentCallbackHandler(CallbackHandler attachmentCallbackHandler) {
        this.attachmentCallbackHandler = attachmentCallbackHandler;
    }

    public boolean isStoreBytesInAttachment() {
        return storeBytesInAttachment;
    }

    public void setStoreBytesInAttachment(boolean storeBytesInAttachment) {
        this.storeBytesInAttachment = storeBytesInAttachment;
    }

    public Serializer getEncryptionSerializer() {
        return encryptionSerializer;
    }

    public void setEncryptionSerializer(Serializer encryptionSerializer) {
        this.encryptionSerializer = encryptionSerializer;
    }

}
