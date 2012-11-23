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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoType;
import org.apache.ws.security.message.token.BinarySecurity;
import org.apache.ws.security.message.token.DOMX509Data;
import org.apache.ws.security.message.token.DOMX509IssuerSerial;
import org.apache.ws.security.message.token.Reference;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.message.token.X509Security;
import org.apache.ws.security.util.UUIDGenerator;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

/**
 * Builder class to build an EncryptedKey.
 * 
 * This is especially useful in the case where the same
 * <code>EncryptedKey</code> has to be used to sign and encrypt the message In
 * such a situation this builder will add the <code>EncryptedKey</code> to the
 * security header and we can use the information form the builder to provide to
 * other builders to reference to the token
 */
public class WSSecEncryptedKey extends WSSecBase {

    private static org.apache.commons.logging.Log log = 
        org.apache.commons.logging.LogFactory.getLog(WSSecEncryptedKey.class);

    protected Document document;

    /**
     * soap:Envelope element
     */
    protected Element envelope = null;

    /**
     * Session key used as the secret in key derivation
     */
    protected byte[] ephemeralKey;
    
    /**
     * Symmetric key used in the EncryptedKey.
     */
    protected SecretKey symmetricKey = null;

    /**
     * Encrypted bytes of the ephemeral key
     */
    protected byte[] encryptedEphemeralKey;
    
    /**
     * Remote user's alias to obtain the cert to encrypt the ephemeral key
     */
    protected String encrUser = null;

    /**
     * Algorithm used to encrypt the ephemeral key
     */
    protected String keyEncAlgo = WSConstants.KEYTRANSPORT_RSAOEP;
    
    /**
     * Algorithm to be used with the ephemeral key
     */
    protected String symEncAlgo = WSConstants.AES_128;
    
    /**
     * Digest Algorithm to be used with RSA-OAEP. The default is SHA-1 (which is not
     * written out unless it is explicitly configured).
     */
    protected String digestAlgo = null;

    /**
     * xenc:EncryptedKey element
     */
    protected Element encryptedKeyElement = null;

    /**
     * The Token identifier of the token that the <code>DerivedKeyToken</code>
     * is (or to be) derived from.
     */
    protected String encKeyId = null;

    /**
     * Custom token value
     */
    protected String customEKTokenValueType;
    
    /**
     * Custom token id
     */
    protected String customEKTokenId;
    
    /**
     * BinarySecurityToken to be included in the case where BST_DIRECT_REFERENCE
     * is used to refer to the asymmetric encryption cert
     */
    protected BinarySecurity bstToken = null;
    
    protected X509Certificate useThisCert = null;
    
    public WSSecEncryptedKey() {
        super();
    }
    
    public WSSecEncryptedKey(WSSConfig config) {
        super(config);
    }

    /**
     * Set the user name to get the encryption certificate.
     * 
     * The public key of this certificate is used, thus no password necessary.
     * The user name is a keystore alias usually.
     * 
     * @param user
     */
    public void setUserInfo(String user) {
        this.user = user;
    }

    /**
     * Get the id generated during <code>prepare()</code>.
     * 
     * Returns the the value of wsu:Id attribute of the EncryptedKey element.
     * 
     * @return Return the wsu:Id of this token or null if <code>prepare()</code>
     *         was not called before.
     */
    public String getId() {
        return encKeyId;
    }

    /**
     * Prepare the ephemeralKey and the tokens required to be added to the
     * security header
     * 
     * @param doc The SOAP envelope as <code>Document</code>
     * @param crypto An instance of the Crypto API to handle keystore and certificates
     * @throws WSSecurityException
     */
    public void prepare(Document doc, Crypto crypto) throws WSSecurityException {

        document = doc;

        //
        // Set up the ephemeral key
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
        X509Certificate remoteCert = useThisCert;
        if (remoteCert == null) {
            CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
            cryptoType.setAlias(user);
            X509Certificate[] certs = crypto.getX509Certificates(cryptoType);
            if (certs == null || certs.length <= 0) {
                throw new WSSecurityException(
                    WSSecurityException.FAILURE,
                    "noUserCertsFound", 
                    new Object[] {user, "encryption"}
                );
            }
            remoteCert = certs[0];
        }
        
        prepareInternal(symmetricKey, remoteCert, crypto);
    }

    /**
     * Encrypt the symmetric key data and prepare the EncryptedKey element
     * 
     * This method does the most work for to prepare the EncryptedKey element.
     * It is also used by the WSSecEncrypt sub-class.
     * 
     * @param secretKey The symmetric key
     * @param remoteCert The certificate that contains the public key to encrypt the
     *                   symmetric key data
     * @param crypto An instance of the Crypto API to handle keystore and certificates
     * @throws WSSecurityException
     */
    protected void prepareInternal(
        SecretKey secretKey, 
        X509Certificate remoteCert,
        Crypto crypto
    ) throws WSSecurityException {
        Cipher cipher = WSSecurityUtil.getCipherInstance(keyEncAlgo);
        try {
            OAEPParameterSpec oaepParameterSpec = null;
            if (WSConstants.KEYTRANSPORT_RSAOEP.equals(keyEncAlgo)) {
                String jceDigestAlgorithm = "SHA-1";
                if (digestAlgo != null) {
                    jceDigestAlgorithm = JCEMapper.translateURItoJCEID(digestAlgo);
                }
                
                oaepParameterSpec = 
                    new OAEPParameterSpec(
                        jceDigestAlgorithm, "MGF1", new MGF1ParameterSpec("SHA-1"), PSource.PSpecified.DEFAULT
                    );
            }
            if (oaepParameterSpec == null) {
                cipher.init(Cipher.WRAP_MODE, remoteCert);
            } else {
                cipher.init(Cipher.WRAP_MODE, remoteCert.getPublicKey(), oaepParameterSpec);
            }
        } catch (InvalidKeyException e) {
            throw new WSSecurityException(
                WSSecurityException.FAILED_ENCRYPTION, null, null, e
            );
        } catch (InvalidAlgorithmParameterException e) {
            throw new WSSecurityException(
                WSSecurityException.FAILED_ENCRYPTION, null, null, e
            );
        }
        int blockSize = cipher.getBlockSize();
        if (doDebug) {
            log.debug(
                "cipher blksize: " + blockSize + ", symm key: " + secretKey.toString()
            );
        }
        
        try {
            encryptedEphemeralKey = cipher.wrap(secretKey);
        } catch (IllegalStateException ex) {
            throw new WSSecurityException(
                WSSecurityException.FAILED_ENCRYPTION, null, null, ex
            );
        } catch (IllegalBlockSizeException ex) {
            throw new WSSecurityException(
                WSSecurityException.FAILED_ENCRYPTION, null, null, ex
            );
        } catch (InvalidKeyException ex) {
            throw new WSSecurityException(
                WSSecurityException.FAILED_ENCRYPTION, null, null, ex
            );
        }
        Text keyText = 
            WSSecurityUtil.createBase64EncodedTextNode(document, encryptedEphemeralKey);

        //
        // Now we need to setup the EncryptedKey header block 1) create a
        // EncryptedKey element and set a wsu:Id for it 2) Generate ds:KeyInfo
        // element, this wraps the wsse:SecurityTokenReference 3) Create and set
        // up the SecurityTokenReference according to the keyIdentifier parameter
        // 4) Create the CipherValue element structure and insert the encrypted
        // session key
        //
        encryptedKeyElement = createEncryptedKey(document, keyEncAlgo);
        if (encKeyId == null || "".equals(encKeyId)) {
            encKeyId = "EK-" + UUIDGenerator.getUUID();
        }
        encryptedKeyElement.setAttributeNS(null, "Id", encKeyId);

        SecurityTokenReference secToken = new SecurityTokenReference(document);

        switch (keyIdentifierType) {
        case WSConstants.X509_KEY_IDENTIFIER:
            secToken.setKeyIdentifier(remoteCert);
            break;

        case WSConstants.SKI_KEY_IDENTIFIER:
            secToken.setKeyIdentifierSKI(remoteCert, crypto);
            break;

        case WSConstants.THUMBPRINT_IDENTIFIER:
        case WSConstants.ENCRYPTED_KEY_SHA1_IDENTIFIER:
            //
            // This identifier is not applicable for this case, so fall back to
            // ThumbprintRSA.
            //
            secToken.setKeyIdentifierThumb(remoteCert);
            break;

        case WSConstants.ISSUER_SERIAL:
            String issuer = remoteCert.getIssuerX500Principal().getName();
            java.math.BigInteger serialNumber = remoteCert.getSerialNumber();
            DOMX509IssuerSerial domIssuerSerial = 
                new DOMX509IssuerSerial(
                    document, issuer, serialNumber
                );
            DOMX509Data domX509Data = new DOMX509Data(document, domIssuerSerial);
            secToken.setX509Data(domX509Data);
            break;

        case WSConstants.BST_DIRECT_REFERENCE:
            Reference ref = new Reference(document);
            String certUri = UUIDGenerator.getUUID();
            ref.setURI("#" + certUri);
            bstToken = new X509Security(document);
            ((X509Security) bstToken).setX509Certificate(remoteCert);
            bstToken.setID(certUri);
            ref.setValueType(bstToken.getValueType());
            secToken.setReference(ref);
            break;
            
        case WSConstants.CUSTOM_SYMM_SIGNING :
            Reference refCust = new Reference(document);
            if (WSConstants.WSS_SAML_KI_VALUE_TYPE.equals(customEKTokenValueType)) {
                secToken.addTokenType(WSConstants.WSS_SAML_TOKEN_TYPE);
                refCust.setValueType(customEKTokenValueType);
            } else if (WSConstants.WSS_SAML2_KI_VALUE_TYPE.equals(customEKTokenValueType)) {
                secToken.addTokenType(WSConstants.WSS_SAML2_TOKEN_TYPE);
            } else if (WSConstants.WSS_ENC_KEY_VALUE_TYPE.equals(customEKTokenValueType)) {
                secToken.addTokenType(WSConstants.WSS_ENC_KEY_VALUE_TYPE);
                refCust.setValueType(customEKTokenValueType);
            } else {
                refCust.setValueType(customEKTokenValueType);
            }
            refCust.setURI("#" + customEKTokenId);
            secToken.setReference(refCust);
            break;
            
        case WSConstants.CUSTOM_SYMM_SIGNING_DIRECT :
            Reference refCustd = new Reference(document);
            if (WSConstants.WSS_SAML_KI_VALUE_TYPE.equals(customEKTokenValueType)) {
                secToken.addTokenType(WSConstants.WSS_SAML_TOKEN_TYPE);
                refCustd.setValueType(customEKTokenValueType);
            } else if (WSConstants.WSS_SAML2_KI_VALUE_TYPE.equals(customEKTokenValueType)) {
                secToken.addTokenType(WSConstants.WSS_SAML2_TOKEN_TYPE);
            }  else if (WSConstants.WSS_ENC_KEY_VALUE_TYPE.equals(customEKTokenValueType)) {
                secToken.addTokenType(WSConstants.WSS_ENC_KEY_VALUE_TYPE);
                refCustd.setValueType(customEKTokenValueType);
            } else {
                refCustd.setValueType(customEKTokenValueType);
            }
            refCustd.setURI(customEKTokenId);
            secToken.setReference(refCustd);
            break;
            
        case WSConstants.CUSTOM_KEY_IDENTIFIER:
            secToken.setKeyIdentifier(customEKTokenValueType, customEKTokenId);
            if (WSConstants.WSS_SAML_KI_VALUE_TYPE.equals(customEKTokenValueType)) {
                secToken.addTokenType(WSConstants.WSS_SAML_TOKEN_TYPE);
            } else if (WSConstants.WSS_SAML2_KI_VALUE_TYPE.equals(customEKTokenValueType)) {
                secToken.addTokenType(WSConstants.WSS_SAML2_TOKEN_TYPE);
            } else if (WSConstants.WSS_ENC_KEY_VALUE_TYPE.equals(customEKTokenValueType)) {
                secToken.addTokenType(WSConstants.WSS_ENC_KEY_VALUE_TYPE);
            } else if (SecurityTokenReference.ENC_KEY_SHA1_URI.equals(customEKTokenValueType)) {
                secToken.addTokenType(WSConstants.WSS_ENC_KEY_VALUE_TYPE);
            }
            break;           

        default:
            throw new WSSecurityException(WSSecurityException.FAILURE, "unsupportedKeyId");
        }
        Element keyInfoElement = 
            document.createElementNS(
                WSConstants.SIG_NS, WSConstants.SIG_PREFIX + ":" + WSConstants.KEYINFO_LN
            );
        keyInfoElement.setAttributeNS(
            WSConstants.XMLNS_NS, "xmlns:" + WSConstants.SIG_PREFIX, WSConstants.SIG_NS
        );
        keyInfoElement.appendChild(secToken.getElement());
        encryptedKeyElement.appendChild(keyInfoElement);

        Element xencCipherValue = createCipherValue(document, encryptedKeyElement);
        xencCipherValue.appendChild(keyText);

        envelope = document.getDocumentElement();
    }

    protected KeyGenerator getKeyGenerator() throws WSSecurityException {
        try {
            //
            // Assume AES as default, so initialize it
            //
            String keyAlgorithm = JCEMapper.getJCEKeyAlgorithmFromURI(symEncAlgo);
            if (keyAlgorithm == null || "".equals(keyAlgorithm)) {
                keyAlgorithm = JCEMapper.translateURItoJCEID(symEncAlgo);
            }
            KeyGenerator keyGen = KeyGenerator.getInstance(keyAlgorithm);
            if (symEncAlgo.equalsIgnoreCase(WSConstants.AES_128)
                || symEncAlgo.equalsIgnoreCase(WSConstants.AES_128_GCM)) {
                keyGen.init(128);
            } else if (symEncAlgo.equalsIgnoreCase(WSConstants.AES_192)
                || symEncAlgo.equalsIgnoreCase(WSConstants.AES_192_GCM)) {
                keyGen.init(192);
            } else if (symEncAlgo.equalsIgnoreCase(WSConstants.AES_256)
                || symEncAlgo.equalsIgnoreCase(WSConstants.AES_256_GCM)) {
                keyGen.init(256);
            }
            return keyGen;
        } catch (NoSuchAlgorithmException e) {
            throw new WSSecurityException(
                WSSecurityException.UNSUPPORTED_ALGORITHM, null, null, e
            );
        }
    }

    /**
     * Create DOM subtree for <code>xenc:EncryptedKey</code>
     * 
     * @param doc the SOAP envelope parent document
     * @param keyTransportAlgo specifies which algorithm to use to encrypt the symmetric key
     * @return an <code>xenc:EncryptedKey</code> element
     */
    protected Element createEncryptedKey(Document doc, String keyTransportAlgo) {
        Element encryptedKey = 
            doc.createElementNS(WSConstants.ENC_NS, WSConstants.ENC_PREFIX + ":EncryptedKey");

        WSSecurityUtil.setNamespace(encryptedKey, WSConstants.ENC_NS, WSConstants.ENC_PREFIX);
        Element encryptionMethod = 
            doc.createElementNS(WSConstants.ENC_NS, WSConstants.ENC_PREFIX + ":EncryptionMethod");
        encryptionMethod.setAttributeNS(null, "Algorithm", keyTransportAlgo);
        
        if (digestAlgo != null) {
            Element digestElement = 
                XMLUtils.createElementInSignatureSpace(doc, Constants._TAG_DIGESTMETHOD);
            digestElement.setAttributeNS(null, "Algorithm", digestAlgo);
            encryptionMethod.appendChild(digestElement);
        }
        
        encryptedKey.appendChild(encryptionMethod);
        return encryptedKey;
    }
    
    protected Element createCipherValue(Document doc, Element encryptedKey) {
        Element cipherData = 
            doc.createElementNS(WSConstants.ENC_NS, WSConstants.ENC_PREFIX + ":CipherData");
        Element cipherValue = 
            doc.createElementNS(WSConstants.ENC_NS, WSConstants.ENC_PREFIX + ":CipherValue");
        cipherData.appendChild(cipherValue);
        encryptedKey.appendChild(cipherData);
        return cipherValue;
    }

    /**
     * Prepend the EncryptedKey element to the elements already in the Security
     * header.
     * 
     * The method can be called any time after <code>prepare()</code>. This
     * allows to insert the EncryptedKey element at any position in the Security
     * header.
     * 
     * @param secHeader The security header that holds the Signature element.
     */
    public void prependToHeader(WSSecHeader secHeader) {
        WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), encryptedKeyElement);
    }

    /**
     * Append the EncryptedKey element to the elements already in the Security
     * header.
     * 
     * The method can be called any time after <code>prepare()</code>. This
     * allows to insert the EncryptedKey element at any position in the Security
     * header.
     * 
     * @param secHeader The security header that holds the Signature element.
     */
    public void appendToHeader(WSSecHeader secHeader) {
        Element secHeaderElement = secHeader.getSecurityHeader();
        secHeaderElement.appendChild(encryptedKeyElement);
    }
    
    /**
     * Prepend the BinarySecurityToken to the elements already in the Security
     * header.
     * 
     * The method can be called any time after <code>prepare()</code>. This
     * allows to insert the BST element at any position in the Security header.
     * 
     * @param secHeader The security header that holds the BST element.
     */
    public void prependBSTElementToHeader(WSSecHeader secHeader) {
        if (bstToken != null) {
            WSSecurityUtil.prependChildElement(
                secHeader.getSecurityHeader(), bstToken.getElement()
            );
        }
        bstToken = null;
    }

    /**
     * Append the BinarySecurityToken to the elements already in the Security
     * header.
     * 
     * The method can be called any time after <code>prepare()</code>. This
     * allows to insert the BST element at any position in the Security header.
     * 
     * @param secHeader The security header that holds the BST element.
     */
    public void appendBSTElementToHeader(WSSecHeader secHeader) {
        if (bstToken != null) {
            Element secHeaderElement = secHeader.getSecurityHeader();
            secHeaderElement.appendChild(bstToken.getElement());
        }
        bstToken = null;
    }
    
    /**
     * @return Returns the ephemeralKey.
     */
    public byte[] getEphemeralKey() {
        return ephemeralKey;
    }
    
    /**
     * Set the X509 Certificate to use for encryption.
     * 
     * If this is set <b>and</b> the key identifier is set to
     * <code>DirectReference</code> then use this certificate to get the
     * public key for encryption.
     * 
     * @param cert is the X509 certificate to use for encryption
     */
    public void setUseThisCert(X509Certificate cert) {
        useThisCert = cert;
    }

    /**
     * @return Returns the encryptedKeyElement.
     */
    public Element getEncryptedKeyElement() {
        return encryptedKeyElement;
    }
    
    /**
     * Set the encrypted key element when a pre prepared encrypted key is used
     * @param encryptedKeyElement EncryptedKey element of the encrypted key used
     */
    public void setEncryptedKeyElement(Element encryptedKeyElement) {
        this.encryptedKeyElement = encryptedKeyElement;
    }
    
    /**
     * @return Returns the BinarySecurityToken element.
     */
    public Element getBinarySecurityTokenElement() {
        if (bstToken != null) {
            return bstToken.getElement();
        }
        return null;
    }
    
    public void setKeyEncAlgo(String keyEncAlgo) {
        this.keyEncAlgo = keyEncAlgo;
    }

    /**
     * @param ephemeralKey The ephemeralKey to set.
     */
    public void setEphemeralKey(byte[] ephemeralKey) {
        this.ephemeralKey = ephemeralKey;
    }
    
    /**
     * Get the id of the BSt generated  during <code>prepare()</code>.
     * 
     * @return Returns the the value of wsu:Id attribute of the 
     * BinaruSecurityToken element.
     */
    public String getBSTTokenId() {
        if (bstToken == null) {
            return null;
        }
        
        return bstToken.getID();
    }

    /**
     * @param document The document to set.
     */
    public void setDocument(Document document) {
        this.document = document;
    }

    /**
     * @param encKeyId The encKeyId to set.
     */
    public void setEncKeyId(String encKeyId) {
        this.encKeyId = encKeyId;
    }
    
    public boolean isCertSet() {
        if (useThisCert == null) {
            return false;
        }
        return true;
    }

    public byte[] getEncryptedEphemeralKey() {
        return encryptedEphemeralKey;
    }
    
    public void setCustomEKTokenValueType(String customEKTokenValueType) {
        this.customEKTokenValueType = customEKTokenValueType;
    }

    public void setCustomEKTokenId(String customEKTokenId) {
        this.customEKTokenId = customEKTokenId;
    }
    
    /**
     * Set the name of the symmetric encryption algorithm to use.
     * 
     * This encryption algorithm is used to encrypt the data. If the algorithm
     * is not set then AES128 is used. Refer to WSConstants which algorithms are
     * supported.
     * 
     * @param algo Is the name of the encryption algorithm
     * @see WSConstants#TRIPLE_DES
     * @see WSConstants#AES_128
     * @see WSConstants#AES_192
     * @see WSConstants#AES_256
     */
    public void setSymmetricEncAlgorithm(String algo) {
        symEncAlgo = algo;
    }

    
    /**
     * Get the name of symmetric encryption algorithm to use.
     * 
     * The name of the encryption algorithm to encrypt the data, i.e. the SOAP
     * Body. Refer to WSConstants which algorithms are supported.
     * 
     * @return the name of the currently selected symmetric encryption algorithm
     * @see WSConstants#TRIPLE_DES
     * @see WSConstants#AES_128
     * @see WSConstants#AES_192
     * @see WSConstants#AES_256
     */
    public String getSymmetricEncAlgorithm() {
        return symEncAlgo;
    }
    
    /**
     * Set the digest algorithm to use with the RSA-OAEP key transport algorithm. The
     * default is SHA-1.
     * 
     * @param digestAlgorithm the digest algorithm to use with the RSA-OAEP key transport algorithm
     */
    public void setDigestAlgorithm(String digestAlgorithm) {
        this.digestAlgo = digestAlgorithm;
    }
    
    /**
     * Get the digest algorithm to use with the RSA-OAEP key transport algorithm. The
     * default is SHA-1.
     */
    public String getDigestAlgorithm() {
        return digestAlgo;
    }
    
    /**
     * @return The symmetric key
     */
    public SecretKey getSymmetricKey() {
        return symmetricKey;
    }

    /**
     * Set the symmetric key to be used for encryption
     * 
     * @param key
     */
    public void setSymmetricKey(SecretKey key) {
        this.symmetricKey = key;
    }


}
