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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.token.BinarySecurity;
import org.apache.wss4j.common.token.DOMX509Data;
import org.apache.wss4j.common.token.DOMX509IssuerSerial;
import org.apache.wss4j.common.token.Reference;
import org.apache.wss4j.common.token.SecurityTokenReference;
import org.apache.wss4j.common.token.X509Security;
import org.apache.wss4j.common.util.KeyUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.stax.impl.util.IDGenerator;
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

    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(WSSecEncryptedKey.class);

    protected Document document;

    /**
     * Encrypted bytes of the ephemeral key
     */
    protected byte[] encryptedEphemeralKey;

    /**
     * Session key used as the secret in key derivation
     */
    private byte[] ephemeralKey;

    /**
     * Symmetric key used in the EncryptedKey.
     */
    protected SecretKey symmetricKey;

    /**
     * Algorithm used to encrypt the ephemeral key
     */
    private String keyEncAlgo = WSConstants.KEYTRANSPORT_RSAOAEP;

    /**
     * Algorithm to be used with the ephemeral key
     */
    private String symEncAlgo = WSConstants.AES_128;

    /**
     * Digest Algorithm to be used with RSA-OAEP. The default is SHA-1 (which is not
     * written out unless it is explicitly configured).
     */
    private String digestAlgo;

    /**
     * MGF Algorithm to be used with RSA-OAEP. The default is MGF-SHA-1 (which is not
     * written out unless it is explicitly configured).
     */
    private String mgfAlgo;

    /**
     * xenc:EncryptedKey element
     */
    private Element encryptedKeyElement;

    /**
     * The Token identifier of the token that the <code>DerivedKeyToken</code>
     * is (or to be) derived from.
     */
    private String encKeyId;

    /**
     * BinarySecurityToken to be included in the case where BST_DIRECT_REFERENCE
     * is used to refer to the asymmetric encryption cert
     */
    private BinarySecurity bstToken;

    private X509Certificate useThisCert;
    
    private PublicKey useThisPublicKey;

    /**
     * Custom token value
     */
    private String customEKTokenValueType;

    /**
     * Custom token id
     */
    private String customEKTokenId;

    private boolean bstAddedToSecurityHeader;
    private boolean includeEncryptionToken;
    private Element customEKKeyInfoElement;

    public WSSecEncryptedKey(WSSecHeader securityHeader) {
        super(securityHeader);
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

    public void clean() {
        ephemeralKey = null;
        symmetricKey = null;
        encryptedEphemeralKey = null;
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
        // Set up the symmetric key
        //
        if (symmetricKey == null) {
            if (ephemeralKey != null) {
                symmetricKey = KeyUtils.prepareSecretKey(symEncAlgo, ephemeralKey);
            } else {
                KeyGenerator keyGen = KeyUtils.getKeyGenerator(symEncAlgo);
                symmetricKey = keyGen.generateKey();
                ephemeralKey = symmetricKey.getEncoded();
            }
        }

        if (encryptedEphemeralKey == null) {
            if (useThisPublicKey != null) {
                prepareInternal(symmetricKey, useThisPublicKey, crypto);
            } else {
                //
                // Get the certificate that contains the public key for the public key
                // algorithm that will encrypt the generated symmetric (session) key.
                //
                X509Certificate remoteCert = useThisCert;
                if (remoteCert == null) {
                    CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
                    cryptoType.setAlias(user);
                    if (crypto == null) {
                        throw new WSSecurityException(
                                                      WSSecurityException.ErrorCode.FAILURE,
                                                      "noUserCertsFound",
                                                      new Object[] {user, "encryption"});
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
        } else {
            prepareInternal(symmetricKey);
        }
    }
    
    private void encryptSymmetricKey(PublicKey encryptingKey, SecretKey keyToBeEncrypted) 
        throws WSSecurityException {
        Cipher cipher = KeyUtils.getCipherInstance(keyEncAlgo);
        try {
            OAEPParameterSpec oaepParameterSpec = null;
            if (WSConstants.KEYTRANSPORT_RSAOAEP.equals(keyEncAlgo)
                    || WSConstants.KEYTRANSPORT_RSAOAEP_XENC11.equals(keyEncAlgo)) {
                String jceDigestAlgorithm = "SHA-1";
                if (digestAlgo != null) {
                    jceDigestAlgorithm = JCEMapper.translateURItoJCEID(digestAlgo);
                }

                MGF1ParameterSpec mgf1ParameterSpec = new MGF1ParameterSpec("SHA-1");
                if (WSConstants.KEYTRANSPORT_RSAOAEP_XENC11.equals(keyEncAlgo)) {
                    if (WSConstants.MGF_SHA224.equals(mgfAlgo)) {
                        mgf1ParameterSpec = new MGF1ParameterSpec("SHA-224");
                    } else if (WSConstants.MGF_SHA256.equals(mgfAlgo)) {
                        mgf1ParameterSpec = new MGF1ParameterSpec("SHA-256");
                    } else if (WSConstants.MGF_SHA384.equals(mgfAlgo)) {
                        mgf1ParameterSpec = new MGF1ParameterSpec("SHA-384");
                    } else if (WSConstants.MGF_SHA512.equals(mgfAlgo)) {
                        mgf1ParameterSpec = new MGF1ParameterSpec("SHA-512");
                    }
                }

                oaepParameterSpec =
                    new OAEPParameterSpec(
                        jceDigestAlgorithm, "MGF1", mgf1ParameterSpec, PSource.PSpecified.DEFAULT
                    );
            }
            if (oaepParameterSpec == null) {
                cipher.init(Cipher.WRAP_MODE, encryptingKey);
            } else {
                cipher.init(Cipher.WRAP_MODE, encryptingKey, oaepParameterSpec);
            }
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.FAILED_ENCRYPTION, e
            );
        }
        int blockSize = cipher.getBlockSize();
        if (doDebug) {
            LOG.debug("cipher blksize: " + blockSize);
        }

        try {
            encryptedEphemeralKey = cipher.wrap(keyToBeEncrypted);
        } catch (IllegalStateException | IllegalBlockSizeException | InvalidKeyException ex) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.FAILED_ENCRYPTION, ex
            );
        }
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
        encryptSymmetricKey(remoteCert.getPublicKey(), secretKey);

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
            encKeyId = IDGenerator.generateID("EK-");
        }
        encryptedKeyElement.setAttributeNS(null, "Id", encKeyId);

        if (customEKKeyInfoElement != null) {
            encryptedKeyElement.appendChild(document.adoptNode(customEKKeyInfoElement));
        } else {
            SecurityTokenReference secToken = new SecurityTokenReference(document);

            switch (keyIdentifierType) {
            case WSConstants.X509_KEY_IDENTIFIER:
                secToken.setKeyIdentifier(remoteCert);
                break;

            case WSConstants.SKI_KEY_IDENTIFIER:
                secToken.setKeyIdentifierSKI(remoteCert, crypto);

                if (includeEncryptionToken) {
                    addBST(remoteCert);
                }
                break;

            case WSConstants.THUMBPRINT_IDENTIFIER:
            case WSConstants.ENCRYPTED_KEY_SHA1_IDENTIFIER:
                //
                // This identifier is not applicable for this case, so fall back to
                // ThumbprintRSA.
                //
                secToken.setKeyIdentifierThumb(remoteCert);

                if (includeEncryptionToken) {
                    addBST(remoteCert);
                }
                break;

            case WSConstants.ISSUER_SERIAL:
                String issuer = remoteCert.getIssuerX500Principal().getName();
                java.math.BigInteger serialNumber = remoteCert.getSerialNumber();
                DOMX509IssuerSerial domIssuerSerial =
                    new DOMX509IssuerSerial(
                        document, issuer, serialNumber
                    );
                DOMX509Data domX509Data = new DOMX509Data(document, domIssuerSerial);
                secToken.setUnknownElement(domX509Data.getElement());

                if (includeEncryptionToken) {
                    addBST(remoteCert);
                }
                break;

            case WSConstants.BST_DIRECT_REFERENCE:
                Reference ref = new Reference(document);
                String certUri = IDGenerator.generateID(null);
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
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "unsupportedKeyId");
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
        }

        Element xencCipherValue = createCipherValue(document, encryptedKeyElement);
        if (storeBytesInAttachment) {
            final String attachmentId = getIdAllocator().createId("", document);
            WSSecurityUtil.storeBytesInAttachment(xencCipherValue, document, attachmentId,
                                                  encryptedEphemeralKey, attachmentCallbackHandler);
        } else {
            Text keyText =
                WSSecurityUtil.createBase64EncodedTextNode(document, encryptedEphemeralKey);
            xencCipherValue.appendChild(keyText);
        }
    }
    
    protected void prepareInternal(
        SecretKey secretKey,
        PublicKey remoteKey,
        Crypto crypto
    ) throws WSSecurityException {
        encryptSymmetricKey(remoteKey, secretKey);

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
            encKeyId = IDGenerator.generateID("EK-");
        }
        encryptedKeyElement.setAttributeNS(null, "Id", encKeyId);

        if (customEKKeyInfoElement != null) {
            encryptedKeyElement.appendChild(document.adoptNode(customEKKeyInfoElement));
        } else {
            SecurityTokenReference secToken = null;
            
            switch (keyIdentifierType) {
            case WSConstants.CUSTOM_SYMM_SIGNING :
                secToken = new SecurityTokenReference(document);
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
                secToken = new SecurityTokenReference(document);
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
                secToken = new SecurityTokenReference(document);
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
                try {
                    XMLSignatureFactory signatureFactory;
                    try {
                        signatureFactory = XMLSignatureFactory.getInstance("DOM", "ApacheXMLDSig");
                    } catch (NoSuchProviderException ex) {
                        signatureFactory = XMLSignatureFactory.getInstance("DOM");
                    }
                    
                    KeyInfoFactory keyInfoFactory = signatureFactory.getKeyInfoFactory();
                    KeyValue keyValue = keyInfoFactory.newKeyValue(remoteKey);
                    String keyInfoUri = getIdAllocator().createSecureId("KI-", null);
                    KeyInfo keyInfo =
                        keyInfoFactory.newKeyInfo(
                            java.util.Collections.singletonList(keyValue), keyInfoUri
                        );
                    
                    keyInfo.marshal(new DOMStructure(encryptedKeyElement), null);
                } catch (java.security.KeyException | MarshalException ex) {
                    LOG.error("", ex);
                    throw new WSSecurityException(
                        WSSecurityException.ErrorCode.FAILED_ENCRYPTION, ex
                    );
                }
            }
            
            if (secToken != null) {
                Element keyInfoElement =
                    document.createElementNS(
                        WSConstants.SIG_NS, WSConstants.SIG_PREFIX + ":" + WSConstants.KEYINFO_LN
                    );
                keyInfoElement.setAttributeNS(
                    WSConstants.XMLNS_NS, "xmlns:" + WSConstants.SIG_PREFIX, WSConstants.SIG_NS
                );
                keyInfoElement.appendChild(secToken.getElement());
                encryptedKeyElement.appendChild(keyInfoElement);
            }
        }

        Element xencCipherValue = createCipherValue(document, encryptedKeyElement);
        if (storeBytesInAttachment) {
            final String attachmentId = getIdAllocator().createId("", document);
            WSSecurityUtil.storeBytesInAttachment(xencCipherValue, document, attachmentId,
                                                  encryptedEphemeralKey, attachmentCallbackHandler);
        } else {
            Text keyText =
                WSSecurityUtil.createBase64EncodedTextNode(document, encryptedEphemeralKey);
            xencCipherValue.appendChild(keyText);
        }
    }

    protected void prepareInternal(SecretKey secretKey) throws WSSecurityException {
        encryptedKeyElement = createEncryptedKey(document, keyEncAlgo);
        if (encKeyId == null || "".equals(encKeyId)) {
            encKeyId = IDGenerator.generateID("EK-");
        }
        encryptedKeyElement.setAttributeNS(null, "Id", encKeyId);

        if (customEKKeyInfoElement != null) {
            encryptedKeyElement.appendChild(document.adoptNode(customEKKeyInfoElement));
        } else if (keyIdentifierType == WSConstants.CUSTOM_SYMM_SIGNING
            || keyIdentifierType == WSConstants.CUSTOM_SYMM_SIGNING_DIRECT
            || keyIdentifierType == WSConstants.CUSTOM_KEY_IDENTIFIER) {
            SecurityTokenReference secToken = new SecurityTokenReference(document);

            switch (keyIdentifierType) {

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
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "unsupportedKeyId");
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
        }

        Element xencCipherValue = createCipherValue(document, encryptedKeyElement);
        if (storeBytesInAttachment) {
            final String attachmentId = getIdAllocator().createId("", document);
            WSSecurityUtil.storeBytesInAttachment(xencCipherValue, document, attachmentId,
                                                  encryptedEphemeralKey, attachmentCallbackHandler);
        } else {
            Text keyText =
                WSSecurityUtil.createBase64EncodedTextNode(document, encryptedEphemeralKey);
            xencCipherValue.appendChild(keyText);
        }
    }

    /**
     * Add a BinarySecurityToken
     */
    private void addBST(X509Certificate cert) throws WSSecurityException {
        bstToken = new X509Security(document);
        ((X509Security) bstToken).setX509Certificate(cert);

        bstAddedToSecurityHeader = false;
        bstToken.setID(IDGenerator.generateID(null));
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

        org.apache.wss4j.common.util.XMLUtils.setNamespace(encryptedKey, WSConstants.ENC_NS, WSConstants.ENC_PREFIX);
        Element encryptionMethod =
            doc.createElementNS(WSConstants.ENC_NS, WSConstants.ENC_PREFIX + ":EncryptionMethod");
        encryptionMethod.setAttributeNS(null, "Algorithm", keyTransportAlgo);

        if (digestAlgo != null) {
            Element digestElement =
                XMLUtils.createElementInSignatureSpace(doc, Constants._TAG_DIGESTMETHOD);
            digestElement.setAttributeNS(null, "Algorithm", digestAlgo);
            encryptionMethod.appendChild(digestElement);
        }
        if (WSConstants.KEYTRANSPORT_RSAOAEP_XENC11.equals(keyEncAlgo) && mgfAlgo != null) {
            Element mgfElement =
                doc.createElementNS(WSConstants.ENC11_NS, WSConstants.ENC11_PREFIX + ":MGF");
            mgfElement.setAttributeNS(null, "Algorithm", mgfAlgo);
            encryptionMethod.appendChild(mgfElement);
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
     */
    public void prependToHeader() {
        Element secHeaderElement = getSecurityHeader().getSecurityHeaderElement();
        WSSecurityUtil.prependChildElement(secHeaderElement, encryptedKeyElement);
    }

    /**
     * Append the EncryptedKey element to the elements already in the Security
     * header.
     *
     * The method can be called any time after <code>prepare()</code>. This
     * allows to insert the EncryptedKey element at any position in the Security
     * header.
     */
    public void appendToHeader() {
        Element secHeaderElement = getSecurityHeader().getSecurityHeaderElement();
        secHeaderElement.appendChild(encryptedKeyElement);
    }

    /**
     * Prepend the BinarySecurityToken to the elements already in the Security
     * header.
     *
     * The method can be called any time after <code>prepare()</code>. This
     * allows to insert the BST element at any position in the Security header.
     */
    public void prependBSTElementToHeader() {
        if (bstToken != null && !bstAddedToSecurityHeader) {
            Element secHeaderElement = getSecurityHeader().getSecurityHeaderElement();
            WSSecurityUtil.prependChildElement(secHeaderElement, bstToken.getElement());
            bstAddedToSecurityHeader = true;
        }
    }

    /**
     * Append the BinarySecurityToken to the elements already in the Security
     * header.
     *
     * The method can be called any time after <code>prepare()</code>. This
     * allows to insert the BST element at any position in the Security header.
     */
    public void appendBSTElementToHeader() {
        if (bstToken != null && !bstAddedToSecurityHeader) {
            Element secHeaderElement = getSecurityHeader().getSecurityHeaderElement();
            secHeaderElement.appendChild(bstToken.getElement());
            bstAddedToSecurityHeader = true;
        }
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
    
    public X509Certificate getUseThisCert() {
        return useThisCert;
    }
    
    /**
     * Set the PublicKey to use for encryption.
     * @param key the PublicKey instance to use for encryption
     */
    public void setUseThisPublicKey(PublicKey key) {
        useThisPublicKey = key;
    }
    
    public PublicKey getUseThisPublicKey() {
        return useThisPublicKey;
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

    public String getKeyEncAlgo() {
        return keyEncAlgo;
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

    public void setEncryptedEphemeralKey(byte[] encryptedKey) {
        encryptedEphemeralKey = encryptedKey;
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
     * Set the MGF algorithm to use with the RSA-OAEP key transport algorithm. The
     * default is MGF-SHA-1.
     *
     * @param mgfAlgorithm the MGF algorithm to use with the RSA-OAEP key transport algorithm
     */
    public void setMGFAlgorithm(String mgfAlgorithm) {
        this.mgfAlgo = mgfAlgorithm;
    }

    /**
     * Get the MGF algorithm to use with the RSA-OAEP key transport algorithm. The
     * default is MGF-SHA-1.
     */
    public String getMGFAlgorithm() {
        return mgfAlgo;
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

    public boolean isIncludeEncryptionToken() {
        return includeEncryptionToken;
    }

    public void setIncludeEncryptionToken(boolean includeEncryptionToken) {
        this.includeEncryptionToken = includeEncryptionToken;
    }

    public Element getCustomEKKeyInfoElement() {
        return customEKKeyInfoElement;
    }

    public void setCustomEKKeyInfoElement(Element customEKKeyInfoElement) {
        this.customEKKeyInfoElement = customEKKeyInfoElement;
    }


}
