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
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.callback.CallbackHandler;

import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.token.Reference;
import org.apache.wss4j.common.token.SecurityTokenReference;
import org.apache.wss4j.common.util.KeyUtils;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WsuIdAllocator;
import org.apache.wss4j.dom.callback.CallbackLookup;
import org.apache.wss4j.dom.message.token.KerberosSecurity;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.apache.xml.security.encryption.Serializer;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.utils.Base64;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

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
    
    private Serializer encryptionSerializer;
    
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
        if (encryptSymmKey && encryptedEphemeralKey == null) {
            if (getUseThisPublicKey() != null) {
                prepareInternal(symmetricKey, getUseThisPublicKey(), crypto);
            } else {
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
                            new Object[] {user, "encryption"});
                    }
                    remoteCert = certs[0];
                }
                prepareInternal(symmetricKey, remoteCert, crypto);
            }
        } else if (encryptedEphemeralKey != null) {
            prepareInternal(symmetricKey);
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

        Element refs = encrypt(secHeader);

        addAttachmentEncryptedDataElements(secHeader);
        if (getEncryptedKeyElement() != null) {
            addInternalRefElement(refs);
            prependToHeader(secHeader);
        } else {
            addExternalRefElement(refs, secHeader);
        }

        prependBSTElementToHeader(secHeader);

        clean();
        LOG.debug("Encryption complete.");
        return doc;
    }

    public Element encrypt() throws WSSecurityException {
        return encrypt(null);
    }
    
    public Element encrypt(WSSecHeader secHeader) throws WSSecurityException {
        if (getParts().isEmpty()) {
            getParts().add(WSSecurityUtil.getDefaultEncryptionPart(document));
        }

        return encryptForRef(null, getParts(), secHeader);
    }
    
    public Element encryptForRef(
        Element dataRef,
        List<WSEncryptionPart> references
    ) throws WSSecurityException {
        return encryptForRef(dataRef, references, null);
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
     * @param secHeader The WSSecHeader instance
     * @return Returns the updated <code>xenc:Reference</code> element
     * @throws WSSecurityException
     */
    public Element encryptForRef(
        Element dataRef,
        List<WSEncryptionPart> references,
        WSSecHeader secHeader
    ) throws WSSecurityException {
        KeyInfo keyInfo = createKeyInfo();
        //the sun/oracle jce provider doesn't like a foreign SecretKey impl.
        //this occurs e.g. with a kerberos session-key. It doesn't matter for the bouncy-castle provider
        //so create a new secretKeySpec to make everybody happy.
        SecretKeySpec secretKeySpec = new SecretKeySpec(symmetricKey.getEncoded(), symmetricKey.getAlgorithm());
        
        Encryptor encryptor = new Encryptor();
        encryptor.setDoc(document);
        encryptor.setSecurityHeader(secHeader);
        encryptor.setIdAllocator(getIdAllocator());
        encryptor.setCallbackLookup(callbackLookup);
        encryptor.setAttachmentCallbackHandler(attachmentCallbackHandler);
        encryptor.setStoreBytesInAttachment(storeBytesInAttachment);
        encryptor.setEncryptionSerializer(getEncryptionSerializer());
        List<String> encDataRefs =
            encryptor.doEncryption(keyInfo, secretKeySpec, getSymmetricEncAlgorithm(), references, attachmentEncryptedDataElements);
        if (encDataRefs.isEmpty()) {
            return null;
        }

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
        if (dataRef != null) {
            getEncryptedKeyElement().appendChild(dataRef);
        }
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
        if (dataRef != null) {
            WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), dataRef);
        }
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
        WSSecHeader securityHeader,
        WsuIdAllocator idAllocator,
        KeyInfo keyInfo,
        SecretKey secretKey,
        String encryptionAlgorithm,
        List<WSEncryptionPart> references,
        CallbackLookup callbackLookup
    ) throws WSSecurityException {
        return doEncryption(
                doc, securityHeader, idAllocator, keyInfo, secretKey, encryptionAlgorithm,
                references, callbackLookup, null, null, false);
    }
    
    public static List<String> doEncryption(
         Document doc,
         WSSecHeader securityHeader,
         WsuIdAllocator idAllocator,
         KeyInfo keyInfo,
         SecretKey secretKey,
         String encryptionAlgorithm,
         List<WSEncryptionPart> references,
         CallbackLookup callbackLookup,
         CallbackHandler attachmentCallbackHandler,
         List<Element> attachmentEncryptedDataElements,
         boolean storeBytesInAttachment
    ) throws WSSecurityException {
        return doEncryption(
                            doc, securityHeader, idAllocator, keyInfo, secretKey, encryptionAlgorithm,
                            references, callbackLookup, attachmentCallbackHandler, 
                            attachmentEncryptedDataElements, storeBytesInAttachment, null);
    }

    public static List<String> doEncryption(
            Document doc,
            WSSecHeader securityHeader,
            WsuIdAllocator idAllocator,
            KeyInfo keyInfo,
            SecretKey secretKey,
            String encryptionAlgorithm,
            List<WSEncryptionPart> references,
            CallbackLookup callbackLookup,
            CallbackHandler attachmentCallbackHandler,
            List<Element> attachmentEncryptedDataElements,
            boolean storeBytesInAttachment,
            Serializer encryptionSerializer
    ) throws WSSecurityException {
        Encryptor encryptor = new Encryptor();
        encryptor.setDoc(doc);
        encryptor.setSecurityHeader(securityHeader);
        encryptor.setIdAllocator(idAllocator);
        encryptor.setCallbackLookup(callbackLookup);
        encryptor.setAttachmentCallbackHandler(attachmentCallbackHandler);
        encryptor.setStoreBytesInAttachment(storeBytesInAttachment);
        encryptor.setEncryptionSerializer(encryptionSerializer);
        return
            encryptor.doEncryption(keyInfo, secretKey, encryptionAlgorithm, references, attachmentEncryptedDataElements);
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
        } else if (!encryptSymmKey && keyIdentifierType == WSConstants.ISSUER_SERIAL) {
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

    public Serializer getEncryptionSerializer() {
        return encryptionSerializer;
    }

    public void setEncryptionSerializer(Serializer encryptionSerializer) {
        this.encryptionSerializer = encryptionSerializer;
    }

}
