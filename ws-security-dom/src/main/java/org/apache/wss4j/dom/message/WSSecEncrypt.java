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

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;

import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.ext.Attachment;
import org.apache.wss4j.common.ext.AttachmentRequestCallback;
import org.apache.wss4j.common.ext.AttachmentResultCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.token.Reference;
import org.apache.wss4j.common.token.SecurityTokenReference;
import org.apache.wss4j.common.util.AttachmentUtils;
import org.apache.wss4j.common.util.KeyUtils;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WsuIdAllocator;
import org.apache.wss4j.dom.message.token.KerberosSecurity;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.utils.Base64;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

/**
 * Encrypts a parts of a message according to WS Specification, X509 profile,
 * and adds the encryption data.
 */
public class WSSecEncrypt extends WSSecEncryptedKey {
    private static final org.slf4j.Logger LOG = 
        org.slf4j.LoggerFactory.getLogger(WSSecEncrypt.class);
    
    /**
     * SecurityTokenReference to be inserted into EncryptedData/keyInfo element.
     */
    private SecurityTokenReference securityTokenReference;

    /**
     * Indicates whether to encrypt the symmetric key into an EncryptedKey 
     * or not.
     */
    private boolean encryptSymmKey = true;
    
    /**
     * Custom reference value
     */
    private String customReferenceValue;

    /**
     * True if the encKeyId is a direct reference to a key identifier instead of a URI to a key
     */
    private boolean encKeyIdDirectId;
    
    private boolean embedEncryptedKey;

    private List<Element> attachmentEncryptedDataElements;
 
    public WSSecEncrypt() {
        super();
    }
    
    /**
     * Initialize a WSSec Encrypt.
     * 
     * The method prepares and initializes a WSSec Encrypt structure after the
     * relevant information was set. After preparation of the token references
     * can be added and encrypted.
     * 
     * This method does not add any element to the security header. This must be
     * done explicitly.
     * 
     * @param doc The SOAP envelope as <code>Document</code>
     * @param crypto An instance of the Crypto API to handle keystore and certificates
     * @throws WSSecurityException
     */
    public void prepare(Document doc, Crypto crypto) throws WSSecurityException {
        document = doc;
        attachmentEncryptedDataElements = new ArrayList<>();

        //
        // Set up the symmetric key
        //
        if (symmetricKey == null) {
            if (getEphemeralKey() != null) {
                symmetricKey = 
                    KeyUtils.prepareSecretKey(getSymmetricEncAlgorithm(), getEphemeralKey());
            } else {
                KeyGenerator keyGen = KeyUtils.getKeyGenerator(getSymmetricEncAlgorithm());
                symmetricKey = keyGen.generateKey();
            }
        }
        
        //
        // Get the certificate that contains the public key for the public key
        // algorithm that will encrypt the generated symmetric (session) key.
        //
        if (encryptSymmKey) {
            X509Certificate remoteCert = getUseThisCert();
            if (remoteCert == null) {
                CryptoType cryptoType = null;
                if (keyIdentifierType == WSConstants.ENDPOINT_KEY_IDENTIFIER) {
                    cryptoType = new CryptoType(CryptoType.TYPE.ENDPOINT);
                    cryptoType.setEndpoint(user);
                } else {
                    cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
                    cryptoType.setAlias(user);
                }
                X509Certificate[] certs = crypto.getX509Certificates(cryptoType);
                if (certs == null || certs.length <= 0) {
                    throw new WSSecurityException(
                        WSSecurityException.ErrorCode.FAILURE,
                        "noUserCertsFound",
                        user, "encryption");
                }
                remoteCert = certs[0];
            }
            prepareInternal(symmetricKey, remoteCert, crypto);
        } else {
            encryptedEphemeralKey = symmetricKey.getEncoded();
        }
    }
    

    /**
     * Builds the SOAP envelope with encrypted Body and adds encrypted key.
     * 
     * This is a convenience method and for backward compatibility. The method
     * calls the single function methods in order to perform a <i>one shot
     * encryption</i>. This method is compatible with the build method of the
     * previous version with the exception of the additional WSSecHeader
     * parameter.
     * 
     * @param doc the SOAP envelope as <code>Document</code> with plain text Body
     * @param crypto an instance of the Crypto API to handle keystore and Certificates
     * @param secHeader the security header element to hold the encrypted key element.
     * @return the SOAP envelope with encrypted Body as <code>Document</code>
     * @throws WSSecurityException
     */
    public Document build(Document doc, Crypto crypto, WSSecHeader secHeader)
        throws WSSecurityException {
        doDebug = LOG.isDebugEnabled();

        prepare(doc, crypto);
        
        if (doDebug) {
            LOG.debug("Beginning Encryption...");
        }
        
        Element refs = encrypt();

        addAttachmentEncryptedDataElements(secHeader);
        if (getEncryptedKeyElement() != null) {
            addInternalRefElement(refs);
            prependToHeader(secHeader); 
        } else {
            addExternalRefElement(refs, secHeader);
        }

        prependBSTElementToHeader(secHeader);

        LOG.debug("Encryption complete.");
        return doc;
    }
    
    public Element encrypt() throws WSSecurityException {
        if (getParts().isEmpty()) {
            getParts().add(WSSecurityUtil.getDefaultEncryptionPart(document));
        }
        
        return encryptForRef(null, getParts());
    }
    
    /**
     * Encrypt one or more parts or elements of the message.
     * 
     * This method takes a vector of <code>WSEncryptionPart</code> object that
     * contain information about the elements to encrypt. The method call the
     * encryption method, takes the reference information generated during
     * encryption and add this to the <code>xenc:Reference</code> element.
     * This method can be called after <code>prepare()</code> and can be
     * called multiple times to encrypt a number of parts or elements.
     * 
     * The method generates a <code>xenc:Reference</code> element that <i>must</i>
     * be added to this token. See <code>addInternalRefElement()</code>.
     * 
     * If the <code>dataRef</code> parameter is <code>null</code> the method
     * creates and initializes a new Reference element.
     * 
     * @param dataRef A <code>xenc:Reference</code> element or <code>null</code>
     * @param references A list containing WSEncryptionPart objects
     * @return Returns the updated <code>xenc:Reference</code> element
     * @throws WSSecurityException
     */
    public Element encryptForRef(
        Element dataRef, 
        List<WSEncryptionPart> references
    ) throws WSSecurityException {
        KeyInfo keyInfo = createKeyInfo();
        //the sun/oracle jce provider doesn't like a foreign SecretKey impl.
        //this occurs e.g. with a kerberos session-key. It doesn't matter for the bouncy-castle provider
        //so create a new secretKeySpec to make everybody happy.
        SecretKeySpec secretKeySpec = new SecretKeySpec(symmetricKey.getEncoded(), symmetricKey.getAlgorithm());
        List<String> encDataRefs = 
            doEncryption(
                document, getIdAllocator(), keyInfo, secretKeySpec, getSymmetricEncAlgorithm(), references, 
                    callbackLookup, attachmentCallbackHandler, attachmentEncryptedDataElements
            );
        if (dataRef == null) {
            dataRef = 
                document.createElementNS(
                    WSConstants.ENC_NS,
                    WSConstants.ENC_PREFIX + ":ReferenceList"
                );
            //
            // If we're not placing the ReferenceList in an EncryptedKey structure,
            // then add the ENC namespace
            //
            if (!encryptSymmKey) {
                XMLUtils.setNamespace(
                    dataRef, WSConstants.ENC_NS, WSConstants.ENC_PREFIX
                );
            }
        }
        return createDataRefList(document, dataRef, encDataRefs);
    }

    /**
     * Adds the internal Reference element to this Encrypt data.
     * 
     * The reference element <i>must</i> be created by the
     * <code>encryptForInternalRef()</code> method. The reference element is
     * added to the <code>EncryptedKey</code> element of this encrypt block.
     * 
     * @param dataRef The internal <code>enc:Reference</code> element
     */
    public void addInternalRefElement(Element dataRef) {
        getEncryptedKeyElement().appendChild(dataRef);
    }

    /**
     * Adds (prepends) the external Reference element to the Security header.
     * 
     * The reference element <i>must</i> be created by the
     * <code>encryptForExternalRef() </code> method. The method prepends the
     * reference element in the SecurityHeader.
     * 
     * @param dataRef The external <code>enc:Reference</code> element
     * @param secHeader The security header.
     */
    public void addExternalRefElement(Element dataRef, WSSecHeader secHeader) {
        WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), dataRef);
    }

    public void addAttachmentEncryptedDataElements(WSSecHeader secHeader) {
        if (attachmentEncryptedDataElements != null) {
            for (int i = 0; i < attachmentEncryptedDataElements.size(); i++) {
                Element encryptedData = attachmentEncryptedDataElements.get(i);
                WSSecurityUtil.prependChildElement(
                        secHeader.getSecurityHeader(), encryptedData
                );
            }
        }
    }

    /**
     * Perform encryption on the SOAP envelope.
     * @param doc The document containing the SOAP envelope as document element
     * @param idAllocator A WsuIdAllocator used to generate wsu:ID's
     * @param keyInfo The KeyInfo object to set in EncryptedData
     * @param secretKey The SecretKey object with which to encrypt data
     * @param encryptionAlgorithm The encryption algorithm URI to use
     * @param references The list of references to encrypt
     * @return a List of references to EncryptedData elements
     * @throws WSSecurityException
     */
    public static List<String> doEncryption(
        Document doc,
        WsuIdAllocator idAllocator,
        KeyInfo keyInfo,
        SecretKey secretKey,
        String encryptionAlgorithm,
        List<WSEncryptionPart> references,
        CallbackLookup callbackLookup
    ) throws WSSecurityException {
        return doEncryption(
                doc, idAllocator, keyInfo, secretKey, encryptionAlgorithm,
                references, callbackLookup, null, null);
    }

    public static List<String> doEncryption(
            Document doc,
            WsuIdAllocator idAllocator,
            KeyInfo keyInfo,
            SecretKey secretKey,
            String encryptionAlgorithm,
            List<WSEncryptionPart> references,
            CallbackLookup callbackLookup,
            CallbackHandler attachmentCallbackHandler,
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
                    "{" + encPart.getNamespace() + "}" + encPart.getName());
            }

            for (Element elementToEncrypt : elementsToEncrypt) {
                String id = 
                    encryptElement(doc, elementToEncrypt, encPart.getEncModifier(), idAllocator, xmlCipher,
                                   secretKey, keyInfo);
                encPart.setEncId(id);
                encDataRef.add("#" + id);
            }
                
            if (part != references.size() - 1) {
                try {
                    keyInfo = new KeyInfo((Element) keyInfo.getElement().cloneNode(true), null);
                } catch (Exception ex) {
                    throw new WSSecurityException(
                        WSSecurityException.ErrorCode.FAILED_ENCRYPTION, ex
                    );
                }
            }
        }

        if (attachmentEncryptionPart != null) {
            // We have an attachment to encrypt

            if (attachmentCallbackHandler == null) {
                throw new WSSecurityException(
                    WSSecurityException.ErrorCode.FAILURE,
                    "empty", "no attachment callbackhandler supplied"
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
                encryptedData.appendChild(keyInfo.getElement());

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

                String jceAlgorithm = JCEMapper.translateURItoJCEID(encryptionAlgorithm);
                Cipher cipher = null;
                try {
                    cipher = Cipher.getInstance(jceAlgorithm);

                    // The Spec mandates a 96-bit IV for GCM algorithms
                    if (XMLCipher.AES_128_GCM.equals(encryptionAlgorithm)
                        || XMLCipher.AES_192_GCM.equals(encryptionAlgorithm)
                        || XMLCipher.AES_256_GCM.equals(encryptionAlgorithm)) {
                        byte[] temp = WSSecurityUtil.generateNonce(12);
                        IvParameterSpec paramSpec = new IvParameterSpec(temp);
                        cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec);
                    } else {
                        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                    }
                } catch (Exception e) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_ENCRYPTION, e);
                }

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

        return encDataRef;
    }

    /**
     * Encrypt an element.
     */
    private static String encryptElement(
        Document doc,
        Element elementToEncrypt,
        String modifier,
        WsuIdAllocator idAllocator,
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
            String headerId = "";
            if ("Header".equals(modifier) 
                && elementToEncrypt.getParentNode().equals(WSSecurityUtil.getSOAPHeader(doc))) {
                Element elem = 
                    doc.createElementNS(
                        WSConstants.WSSE11_NS, "wsse11:" + WSConstants.ENCRYPTED_HEADER
                    );
                XMLUtils.setNamespace(elem, WSConstants.WSSE11_NS, WSConstants.WSSE11_PREFIX);
                String wsuPrefix = 
                    XMLUtils.setNamespace(elem, WSConstants.WSU_NS, WSConstants.WSU_PREFIX);
                headerId = idAllocator.createId("EH-", elementToEncrypt);
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
                
                NamedNodeMap map = elementToEncrypt.getAttributes();
                for (int i = 0; i < map.getLength(); i++) {
                    Attr attr = (Attr)map.item(i);
                    if (attr.getNamespaceURI().equals(WSConstants.URI_SOAP11_ENV)
                        || attr.getNamespaceURI().equals(WSConstants.URI_SOAP12_ENV)) {                         
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
    
    /**
     * Create a KeyInfo object
     */
    private KeyInfo createKeyInfo() throws WSSecurityException {

        KeyInfo keyInfo = new KeyInfo(document);
        if (embedEncryptedKey) {
            keyInfo.addUnknownElement(getEncryptedKeyElement());
        } else if (keyIdentifierType == WSConstants.ENCRYPTED_KEY_SHA1_IDENTIFIER) {
            SecurityTokenReference secToken = new SecurityTokenReference(document);
            secToken.addWSSENamespace();
            if (customReferenceValue != null) {
                secToken.setKeyIdentifierEncKeySHA1(customReferenceValue);
            } else {
                byte[] encodedBytes = KeyUtils.generateDigest(encryptedEphemeralKey);
                secToken.setKeyIdentifierEncKeySHA1(Base64.encode(encodedBytes));
            }
            secToken.addTokenType(WSConstants.WSS_ENC_KEY_VALUE_TYPE);
            keyInfo.addUnknownElement(secToken.getElement());
        } else if (WSConstants.WSS_SAML_KI_VALUE_TYPE.equals(customReferenceValue)) {
            SecurityTokenReference secToken = new SecurityTokenReference(document);
            secToken.addWSSENamespace();
            secToken.addTokenType(WSConstants.WSS_SAML_TOKEN_TYPE);
            secToken.setKeyIdentifier(WSConstants.WSS_SAML_KI_VALUE_TYPE, getId());
            keyInfo.addUnknownElement(secToken.getElement());
        } else if (WSConstants.WSS_SAML2_KI_VALUE_TYPE.equals(customReferenceValue)) {
            SecurityTokenReference secToken = new SecurityTokenReference(document);
            secToken.addWSSENamespace();
            secToken.addTokenType(WSConstants.WSS_SAML2_TOKEN_TYPE);
            secToken.setKeyIdentifier(WSConstants.WSS_SAML2_KI_VALUE_TYPE, getId());
            keyInfo.addUnknownElement(secToken.getElement());
        } else if (WSConstants.WSS_KRB_KI_VALUE_TYPE.equals(customReferenceValue)) {
            SecurityTokenReference secToken = new SecurityTokenReference(document);
            secToken.addWSSENamespace();
            secToken.addTokenType(WSConstants.WSS_GSS_KRB_V5_AP_REQ);
            secToken.setKeyIdentifier(customReferenceValue, getId(), true);
            keyInfo.addUnknownElement(secToken.getElement());
        } else if (securityTokenReference != null) {
            Element tmpE = securityTokenReference.getElement();
            tmpE.setAttributeNS(
                WSConstants.XMLNS_NS, "xmlns:" + tmpE.getPrefix(), tmpE.getNamespaceURI()
            );
            keyInfo.addUnknownElement(securityTokenReference.getElement());
        } else if (getId() != null) {
            SecurityTokenReference secToken = new SecurityTokenReference(document);
            secToken.addWSSENamespace();
            Reference ref = new Reference(document);
            if (encKeyIdDirectId) {
                ref.setURI(getId());
            } else {
                ref.setURI("#" + getId());                    
            }
            if (customReferenceValue != null) {
                ref.setValueType(customReferenceValue);
            }
            secToken.setReference(ref);
            if (KerberosSecurity.isKerberosToken(customReferenceValue)) {
                secToken.addTokenType(customReferenceValue);
            } else if (!WSConstants.WSS_USERNAME_TOKEN_VALUE_TYPE.equals(customReferenceValue)) {
                secToken.addTokenType(WSConstants.WSS_ENC_KEY_VALUE_TYPE);
            }
            keyInfo.addUnknownElement(secToken.getElement());
        }
        Element keyInfoElement = keyInfo.getElement();
        keyInfoElement.setAttributeNS(
            WSConstants.XMLNS_NS, "xmlns:" + WSConstants.SIG_PREFIX, WSConstants.SIG_NS
        );
        
        return keyInfo;
    }

    /**
     * Create DOM subtree for <code>xenc:EncryptedKey</code>
     * 
     * @param doc the SOAP envelope parent document
     * @param referenceList
     * @param encDataRefs
     * @return an <code>xenc:EncryptedKey</code> element
     */
    public static Element createDataRefList(
        Document doc,
        Element referenceList, 
        List<String> encDataRefs
    ) {
        for (String dataReferenceUri : encDataRefs) {
            Element dataReference = 
                doc.createElementNS(
                    WSConstants.ENC_NS, WSConstants.ENC_PREFIX + ":DataReference"
                );
            dataReference.setAttributeNS(null, "URI", dataReferenceUri);
            referenceList.appendChild(dataReference);
        }
        return referenceList;
    }

    /**
     * @return Return the SecurityTokenRefernce
     */
    public SecurityTokenReference getSecurityTokenReference() {
        return securityTokenReference;
    }

    /**
     * @param reference
     */
    public void setSecurityTokenReference(SecurityTokenReference reference) {
        securityTokenReference = reference;
    }

    public boolean isEncryptSymmKey() {
        return encryptSymmKey;
    }
    
    public void setEncryptSymmKey(boolean encryptSymmKey) {
        this.encryptSymmKey = encryptSymmKey;
    }
    
    public void setCustomReferenceValue(String customReferenceValue) {
        this.customReferenceValue = customReferenceValue;
    }
    
    public void setEncKeyIdDirectId(boolean b) {
        encKeyIdDirectId = b;
    }
    
    public void setEmbedEncryptedKey(boolean embedEncryptedKey) {
        this.embedEncryptedKey = embedEncryptedKey;
    }
    
    public boolean isEmbedEncryptedKey() {
        return embedEncryptedKey;
    }

    public List<Element> getAttachmentEncryptedDataElements() {
        return attachmentEncryptedDataElements;
    }

}
