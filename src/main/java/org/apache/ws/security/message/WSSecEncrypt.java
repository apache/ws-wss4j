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

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoType;
import org.apache.ws.security.message.token.KerberosSecurity;
import org.apache.ws.security.message.token.Reference;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.util.Base64;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.keys.KeyInfo;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Encrypts a parts of a message according to WS Specification, X509 profile,
 * and adds the encryption data.
 * 
 * @author Davanum Srinivas (dims@yahoo.com).
 * @author Werner Dittmann (Werner.Dittmann@apache.org).
 */
public class WSSecEncrypt extends WSSecEncryptedKey {
    private static org.apache.commons.logging.Log log = 
        org.apache.commons.logging.LogFactory.getLog(WSSecEncrypt.class);
    
    protected byte[] embeddedKey = null;

    protected String embeddedKeyName = null;

    /**
     * SecurityTokenReference to be inserted into EncryptedData/keyInfo element.
     */
    protected SecurityTokenReference securityTokenReference = null;

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
 
    public WSSecEncrypt() {
        super();
    }
    
    public WSSecEncrypt(WSSConfig config) {
        super(config);
    }
    
    /**
     * Sets the key to use during embedded encryption.
     * 
     * @param key to use during encryption. The key must fit the selected
     *            symmetrical encryption algorithm
     */
    public void setKey(byte[] key) {
        embeddedKey = key;
    }

    /**
     * Sets the algorithm to encode the symmetric key.
     * 
     * Default is the <code>WSConstants.KEYTRANSPORT_RSAOEP</code> algorithm.
     * 
     * @param keyEnc specifies the key encoding algorithm.
     * @see WSConstants#KEYTRANSPORT_RSA15
     * @see WSConstants#KEYTRANSPORT_RSAOEP
     */
    public void setKeyEnc(String keyEnc) {
        keyEncAlgo = keyEnc;
    }

    /**
     * Set the key name for EMBEDDED_KEYNAME
     * 
     * @param embeddedKeyName
     */
    public void setEmbeddedKeyName(String embeddedKeyName) {
        this.embeddedKeyName = embeddedKeyName;
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

        //
        // If no external key (symmetricalKey) was set generate an encryption
        // key (session key) for this Encrypt element. This key will be
        // encrypted using the public key of the receiver
        //
        if (ephemeralKey == null) {
            if (symmetricKey == null) {
                KeyGenerator keyGen = getKeyGenerator();
                symmetricKey = keyGen.generateKey();
            } 
            ephemeralKey = symmetricKey.getEncoded();
        }
        
        if (symmetricKey == null) {
            symmetricKey = WSSecurityUtil.prepareSecretKey(symEncAlgo, ephemeralKey);
        }
        
        //
        // Get the certificate that contains the public key for the public key
        // algorithm that will encrypt the generated symmetric (session) key.
        //
        if (encryptSymmKey) {
            X509Certificate remoteCert = useThisCert;
            if (remoteCert == null) {
                CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
                cryptoType.setAlias(user);
                X509Certificate[] certs = crypto.getX509Certificates(cryptoType);
                if (certs == null || certs.length <= 0) {
                    throw new WSSecurityException(
                        WSSecurityException.FAILURE,
                        "noUserCertsFound", 
                        new Object[] { user, "encryption" }
                    );
                }
                remoteCert = certs[0];
            }
            prepareInternal(symmetricKey, remoteCert, crypto);
        } else {
            encryptedEphemeralKey = ephemeralKey;
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
        doDebug = log.isDebugEnabled();

        if (keyIdentifierType == WSConstants.EMBEDDED_KEYNAME
            || keyIdentifierType == WSConstants.EMBED_SECURITY_TOKEN_REF) {
            encryptSymmKey = false;
            document = doc;
            //
            // Generate a symmetric key from the specified key (password) for this
            // algorithm, and set the cipher into encryption mode.
            //
            if (symmetricKey == null) {
                if (embeddedKey == null) {
                    throw new WSSecurityException(WSSecurityException.FAILURE, "noKeySupplied");
                }
                symmetricKey = WSSecurityUtil.prepareSecretKey(symEncAlgo, embeddedKey);
            }
        } else {
            prepare(doc, crypto);
        }
        
        if (envelope == null) {
            envelope = document.getDocumentElement();
        }
        
        if (parts == null) {
            parts = new ArrayList<WSEncryptionPart>(1);
            String soapNamespace = WSSecurityUtil.getSOAPNamespace(envelope);
            WSEncryptionPart encP = 
                new WSEncryptionPart(
                    WSConstants.ELEM_BODY, 
                    soapNamespace, 
                    "Content"
                );
            parts.add(encP);
        }

        if (doDebug) {
            log.debug("Beginning Encryption...");
        }
        
        Element refs = encryptForRef(null, parts);
        if (encryptedKeyElement != null) {
            addInternalRefElement(refs);
            prependToHeader(secHeader); 
        } else {
            addExternalRefElement(refs, secHeader);
        }

        if (bstToken != null) {
            prependBSTElementToHeader(secHeader);
        }

        log.debug("Encryption complete.");
        return doc;
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
        List<String> encDataRefs = 
            doEncryption(
                document, getWsConfig(), keyInfo, symmetricKey, symEncAlgo, references, callbackLookup
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
                WSSecurityUtil.setNamespace(
                    dataRef, WSConstants.ENC_NS, WSConstants.ENC_PREFIX
                );
            }
        }
        return createDataRefList(document, dataRef, encDataRefs);
    }

    /**
     * @deprecated Use encryptForRef(dataRef, references) instead
     */
    public Element encryptForInternalRef(Element dataRef, List<WSEncryptionPart> references)
        throws WSSecurityException {
        return encryptForRef(dataRef, references);
    }

    /**
     * @deprecated Use encryptForRef(dataRef, references) instead
     */
    public Element encryptForExternalRef(Element dataRef, List<WSEncryptionPart> references)
        throws WSSecurityException {
        return encryptForRef(dataRef, references);
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
        encryptedKeyElement.appendChild(dataRef);
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

    /**
     * Perform encryption on the SOAP envelope.
     * @param doc The document containing the SOAP envelope as document element
     * @param config The WSSConfig from which to generate wsu:ID's
     * @param keyInfo The KeyInfo object to set in EncryptedData
     * @param secretKey The SecretKey object with which to encrypt data
     * @param encryptionAlgorithm The encryption algorithm URI to use
     * @param references The list of references to encrypt
     * @return a List of references to EncryptedData elements
     * @throws WSSecurityException
     */
    public static List<String> doEncryption(
        Document doc,
        WSSConfig config,
        KeyInfo keyInfo,
        SecretKey secretKey,
        String encryptionAlgorithm,
        List<WSEncryptionPart> references,
        CallbackLookup callbackLookup
    ) throws WSSecurityException {

        XMLCipher xmlCipher = null;
        try {
            xmlCipher = XMLCipher.getInstance(encryptionAlgorithm);
        } catch (XMLEncryptionException ex) {
            throw new WSSecurityException(
                WSSecurityException.UNSUPPORTED_ALGORITHM, null, null, ex
            );
        }

        List<String> encDataRef = new ArrayList<String>();
        for (int part = 0; part < references.size(); part++) {
            WSEncryptionPart encPart = references.get(part);
            //
            // Get the data to encrypt.
            //
            if (callbackLookup == null) {
                callbackLookup = new DOMCallbackLookup(doc);
            }
            List<Element> elementsToEncrypt = 
                WSSecurityUtil.findElements(encPart, callbackLookup, doc);
            if (elementsToEncrypt == null || elementsToEncrypt.size() == 0) {
                throw new WSSecurityException(
                    WSSecurityException.FAILURE,
                    "noEncElement", 
                    new Object[] {"{" + encPart.getNamespace() + "}" + encPart.getName()}
                );
            }

            String modifier = encPart.getEncModifier();
            for (Element elementToEncrypt : elementsToEncrypt) {
                String id = 
                    encryptElement(doc, elementToEncrypt, modifier, config, xmlCipher, 
                                   secretKey, keyInfo);
                encPart.setEncId(id);
                encDataRef.add("#" + id);
            }
                
            if (part != (references.size() - 1)) {
                try {
                    keyInfo = new KeyInfo((Element) keyInfo.getElement().cloneNode(true), null);
                } catch (Exception ex) {
                    throw new WSSecurityException(
                        WSSecurityException.FAILED_ENCRYPTION, null, null, ex
                    );
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
        WSSConfig config,
        XMLCipher xmlCipher,
        SecretKey secretKey,
        KeyInfo keyInfo
    ) throws WSSecurityException {

        boolean content = "Content".equals(modifier) ? true : false;
        //
        // Encrypt data, and set necessary attributes in xenc:EncryptedData
        //
        String xencEncryptedDataId = 
            config.getIdAllocator().createId("ED-", elementToEncrypt);
        try {
            String headerId = "";
            if ("Header".equals(modifier)) {
                Element elem = 
                    doc.createElementNS(
                        WSConstants.WSSE11_NS, "wsse11:" + WSConstants.ENCRYPTED_HEADER
                    );
                WSSecurityUtil.setNamespace(elem, WSConstants.WSSE11_NS, WSConstants.WSSE11_PREFIX);
                String wsuPrefix = 
                    WSSecurityUtil.setNamespace(elem, WSConstants.WSU_NS, WSConstants.WSU_PREFIX);
                headerId = config.getIdAllocator().createId("EH-", elementToEncrypt);
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
                            WSSecurityUtil.setNamespace(
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
                WSSecurityException.FAILED_ENCRYPTION, null, null, ex
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
                byte[] encodedBytes = WSSecurityUtil.generateDigest(encryptedEphemeralKey);
                secToken.setKeyIdentifierEncKeySHA1(Base64.encode(encodedBytes));
            }
            secToken.addTokenType(WSConstants.WSS_ENC_KEY_VALUE_TYPE);
            keyInfo.addUnknownElement(secToken.getElement());
        } else if (keyIdentifierType == WSConstants.EMBEDDED_KEYNAME) {
            keyInfo.addKeyName(embeddedKeyName == null ? user : embeddedKeyName);
        } else if (WSConstants.WSS_SAML_KI_VALUE_TYPE.equals(customReferenceValue)) {
            SecurityTokenReference secToken = new SecurityTokenReference(document);
            secToken.addWSSENamespace();
            secToken.addTokenType(WSConstants.WSS_SAML_TOKEN_TYPE);
            secToken.setKeyIdentifier(WSConstants.WSS_SAML_KI_VALUE_TYPE, encKeyId);
            keyInfo.addUnknownElement(secToken.getElement());
        } else if (WSConstants.WSS_SAML2_KI_VALUE_TYPE.equals(customReferenceValue)) {
            SecurityTokenReference secToken = new SecurityTokenReference(document);
            secToken.addWSSENamespace();
            secToken.addTokenType(WSConstants.WSS_SAML2_TOKEN_TYPE);
            secToken.setKeyIdentifier(WSConstants.WSS_SAML2_KI_VALUE_TYPE, encKeyId);
            keyInfo.addUnknownElement(secToken.getElement());
        } else if (WSConstants.WSS_KRB_KI_VALUE_TYPE.equals(customReferenceValue)) {
            SecurityTokenReference secToken = new SecurityTokenReference(document);
            secToken.addWSSENamespace();
            secToken.addTokenType(WSConstants.WSS_GSS_KRB_V5_AP_REQ);
            secToken.setKeyIdentifier(customReferenceValue, encKeyId, true);
            keyInfo.addUnknownElement(secToken.getElement());
        } else if (securityTokenReference != null) {
            Element tmpE = securityTokenReference.getElement();
            tmpE.setAttributeNS(
                WSConstants.XMLNS_NS, "xmlns:" + tmpE.getPrefix(), tmpE.getNamespaceURI()
            );
            keyInfo.addUnknownElement(securityTokenReference.getElement());
        } else {
            SecurityTokenReference secToken = new SecurityTokenReference(document);
            secToken.addWSSENamespace();
            Reference ref = new Reference(document);
            if (encKeyIdDirectId) {
                ref.setURI(encKeyId);
            } else {
                ref.setURI("#" + encKeyId);                    
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
}
