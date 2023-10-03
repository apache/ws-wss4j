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

import org.apache.jcp.xml.dsig.internal.dom.DOMKeyInfoFactory;
import org.apache.wss4j.common.WSS4JConstants;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.derivedKey.AlgoFactory;
import org.apache.wss4j.common.derivedKey.ConversationConstants;
import org.apache.wss4j.common.derivedKey.DerivationAlgorithm;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.token.*;
import org.apache.wss4j.common.util.AttachmentUtils;
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

import javax.crypto.*;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.NamedParameterSpec;

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

    /**
     * Algorithm used to encrypt the ephemeral key
     */
    private String keyEncAlgo = WSConstants.KEYTRANSPORT_RSAOAEP;

    /**
     * Key agreement method algorithm used to encrypt the ephemeral key such as http://www.w3.org/2009/xmlenc11#ECDH-ES
     */
    private String keyAgreementMethod;

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
    private Provider provider;

    private String encryptedKeySHA1;

    public WSSecEncryptedKey(WSSecHeader securityHeader) {
        super(securityHeader);
    }

    public WSSecEncryptedKey(Document doc) {
        this(doc, null);
    }

    public WSSecEncryptedKey(Document doc, Provider provider) {
        super(doc);
        this.provider = provider;
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
     * Create the EncryptedKey Element for inclusion in the security header, by encrypting the
     * symmetricKey parameter using either a public key or certificate that is set on the class,
     * and adding the encrypted bytes as the CipherValue of the EncryptedKey element. The KeyInfo
     * is constructed according to the keyIdentifierType and also the type of the encrypting
     * key
     *
     * @param crypto An instance of the Crypto API to handle keystore and certificates
     * @param symmetricKey The symmetric key to encrypt and insert into the EncryptedKey
     * @throws WSSecurityException
     */
    public void prepare(Crypto crypto, SecretKey symmetricKey) throws WSSecurityException {

        if (useThisPublicKey != null) {
            createEncryptedKeyElement(useThisPublicKey);
            byte[] encryptedEphemeralKey = encryptSymmetricKey(useThisPublicKey, symmetricKey);
            addCipherValueElement(encryptedEphemeralKey);
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

            KeyPair dhKeyPair = null;
            byte[] encryptedEphemeralKey;
            if (WSConstants.AGREEMENT_METHOD_ECDH_ES.equals(keyAgreementMethod)) {
                // generate ephemeral keys the key must match receivers keys
                dhKeyPair = generateEmphemeralDHKeyPair(remoteCert.getPublicKey());
                encryptedEphemeralKey = encryptSymmetricKeyWithDH(remoteCert.getPublicKey(),
                        symmetricKey,
                        dhKeyPair.getPrivate(),
                        WSS4JConstants.KDF_CONCAT);
            } else {
                encryptedEphemeralKey = encryptSymmetricKey(remoteCert.getPublicKey(), symmetricKey);
            }

            createEncryptedKeyElement(remoteCert, crypto, dhKeyPair != null ? dhKeyPair.getPublic() : null);
            addCipherValueElement(encryptedEphemeralKey);
        }
    }

    public KeyPair generateEmphemeralDHKeyPair(PublicKey recipientPublicKey) throws WSSecurityException {
        String algorithm = recipientPublicKey.getAlgorithm();
        KeyPairGenerator keyPairGenerator;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
            if (recipientPublicKey instanceof ECPublicKey) {
                ECPublicKey exchangePublicKey = (ECPublicKey) recipientPublicKey;
                // get keySize
                int keySize = exchangePublicKey.getParams().getCurve().getField().getFieldSize();
                String name = "secp" + keySize + "r1";
                ECGenParameterSpec kpgparams = new ECGenParameterSpec(name);
                keyPairGenerator.initialize(kpgparams);
            } else if (recipientPublicKey instanceof XECPublicKey) {
                XECPublicKey exchangePublicKey = (XECPublicKey) recipientPublicKey;
                String keyName = ((NamedParameterSpec) exchangePublicKey.getParams()).getName();
                ECGenParameterSpec kpgparams = new ECGenParameterSpec(keyName);
                keyPairGenerator.initialize(kpgparams);
            } else {
                throw new WSSecurityException(WSSecurityException.ErrorCode.UNSUPPORTED_ALGORITHM, "Key type is not supported");
            }
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, e);
        }
    }

    /**
     * Create and add the CipherValue Element to the EncryptedKey Element.
     */
    protected void addCipherValueElement(byte[] encryptedEphemeralKey) throws WSSecurityException {
        Element xencCipherValue = createCipherValue(getDocument(), encryptedKeyElement);
        if (storeBytesInAttachment) {
            final String attachmentId = getIdAllocator().createId("", getDocument());
            AttachmentUtils.storeBytesInAttachment(xencCipherValue, getDocument(), attachmentId,
                                                  encryptedEphemeralKey, attachmentCallbackHandler);
        } else {
            Text keyText =
                WSSecurityUtil.createBase64EncodedTextNode(getDocument(), encryptedEphemeralKey);
            xencCipherValue.appendChild(keyText);
        }

        setEncryptedKeySHA1(encryptedEphemeralKey);
    }

    /**
     * Now we need to setup the EncryptedKey header block:
     *  1) create a EncryptedKey element and set a wsu:Id for it
     *  2) Generate ds:KeyInfo element, this wraps the wsse:SecurityTokenReference
     *  3) Create and set up the SecurityTokenReference according to the keyIdentifier parameter
     *  4) Create the CipherValue element structure and insert the encrypted session key
     */
    protected void createEncryptedKeyElement(X509Certificate remoteCert, Crypto crypto, PublicKey dhPublicKey) throws WSSecurityException {
        encryptedKeyElement = createEncryptedKey(getDocument(), keyEncAlgo);
        if (encKeyId == null || encKeyId.length() == 0) {
            encKeyId = IDGenerator.generateID("EK-");
        }
        encryptedKeyElement.setAttributeNS(null, "Id", encKeyId);

        if (customEKKeyInfoElement != null) {
            encryptedKeyElement.appendChild(getDocument().adoptNode(customEKKeyInfoElement));
        } else {
            SecurityTokenReference secToken = new SecurityTokenReference(getDocument());
            if (addWSUNamespace) {
                secToken.addWSUNamespace();
            }

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
                addIssuerSerial(remoteCert, secToken, false);
                break;

            case WSConstants.ISSUER_SERIAL_QUOTE_FORMAT:
                addIssuerSerial(remoteCert, secToken,true);
                break;

            case WSConstants.BST_DIRECT_REFERENCE:
                Reference ref = new Reference(getDocument());
                String certUri = IDGenerator.generateID(null);
                ref.setURI("#" + certUri);
                bstToken = new X509Security(getDocument());
                ((X509Security) bstToken).setX509Certificate(remoteCert);
                bstToken.setID(certUri);
                ref.setValueType(bstToken.getValueType());
                secToken.setReference(ref);
                break;

            case WSConstants.CUSTOM_SYMM_SIGNING :
                Reference refCust = new Reference(getDocument());
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
                Reference refCustd = new Reference(getDocument());
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
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "unsupportedKeyId",
                                              new Object[] {keyIdentifierType});
            }
            Element keyInfoElement =
                getDocument().createElementNS(
                    WSConstants.SIG_NS, WSConstants.SIG_PREFIX + ":" + WSConstants.KEYINFO_LN
                );
            keyInfoElement.setAttributeNS(
                WSConstants.XMLNS_NS, "xmlns:" + WSConstants.SIG_PREFIX, WSConstants.SIG_NS
            );


            if (WSConstants.AGREEMENT_METHOD_ECDH_ES.equals(keyAgreementMethod)) {
                Element agreementMethodElement = createAgreementMethod(getDocument(), keyAgreementMethod, dhPublicKey, secToken);
                keyInfoElement.appendChild(agreementMethodElement);

            } else {
                keyInfoElement.appendChild(secToken.getElement());
            }
            encryptedKeyElement.appendChild(keyInfoElement);
        }

    }

    private void addIssuerSerial(X509Certificate remoteCert, SecurityTokenReference secToken, boolean isCommaDelimited)
            throws WSSecurityException {
        String issuer = remoteCert.getIssuerX500Principal().getName();
        java.math.BigInteger serialNumber = remoteCert.getSerialNumber();
        DOMX509IssuerSerial domIssuerSerial =
                new DOMX509IssuerSerial(getDocument(), issuer, serialNumber, isCommaDelimited);
        DOMX509Data domX509Data = new DOMX509Data(getDocument(), domIssuerSerial);
        secToken.setUnknownElement(domX509Data.getElement());

        if (includeEncryptionToken) {
            addBST(remoteCert);
        }
    }

    /**
     * Now we need to setup the EncryptedKey header block:
     *  1) create a EncryptedKey element and set a wsu:Id for it
     *  2) Generate ds:KeyInfo element, this wraps the wsse:SecurityTokenReference
     *  3) Create and set up the SecurityTokenReference according to the keyIdentifier parameter
     *  4) Create the CipherValue element structure and insert the encrypted session key
     */
    protected void createEncryptedKeyElement(Key key) throws WSSecurityException {
        encryptedKeyElement = createEncryptedKey(getDocument(), keyEncAlgo);
        if (encKeyId == null || encKeyId.length() == 0) {
            encKeyId = IDGenerator.generateID("EK-");
        }
        encryptedKeyElement.setAttributeNS(null, "Id", encKeyId);

        if (customEKKeyInfoElement != null) {
            encryptedKeyElement.appendChild(getDocument().adoptNode(customEKKeyInfoElement));
        } else {
            SecurityTokenReference secToken = new SecurityTokenReference(getDocument());
            if (addWSUNamespace) {
                secToken.addWSUNamespace();
            }

            switch (keyIdentifierType) {

                case WSConstants.CUSTOM_SYMM_SIGNING :
                    Reference refCust = new Reference(getDocument());
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
                    Reference refCustd = new Reference(getDocument());
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

                case WSConstants.KEY_VALUE:
                    // This is only applicable for the PublicKey case
                    if (!(key instanceof PublicKey)) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "unsupportedKeyId",
                                                      new Object[] {keyIdentifierType});
                    }
                    try {
                        XMLSignatureFactory signatureFactory;
                        if (provider == null) {
                            // Try to install the Santuario Provider - fall back to the JDK provider if this does
                            // not work
                            try {
                                signatureFactory = XMLSignatureFactory.getInstance("DOM", "ApacheXMLDSig");
                            } catch (NoSuchProviderException ex) {
                                signatureFactory = XMLSignatureFactory.getInstance("DOM");
                            }
                        } else {
                            signatureFactory = XMLSignatureFactory.getInstance("DOM", provider);
                        }

                        KeyInfoFactory keyInfoFactory = signatureFactory.getKeyInfoFactory();
                        KeyValue keyValue = keyInfoFactory.newKeyValue((PublicKey)key);
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
                    break;

                default:
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "unsupportedKeyId",
                                                  new Object[] {keyIdentifierType});
            }

            if (WSConstants.KEY_VALUE != keyIdentifierType) {
                Element keyInfoElement =
                    getDocument().createElementNS(
                        WSConstants.SIG_NS, WSConstants.SIG_PREFIX + ":" + WSConstants.KEYINFO_LN
                    );
                keyInfoElement.setAttributeNS(
                    WSConstants.XMLNS_NS, "xmlns:" + WSConstants.SIG_PREFIX, WSConstants.SIG_NS
                );
                keyInfoElement.appendChild(secToken.getElement());
                encryptedKeyElement.appendChild(keyInfoElement);
            }
        }
    }

    /**
     * Encrypt the symmetric key  using DH derived key using ConcatKDF DH secret produced from originator  and recipient public key.
     *
     * @param recipientPublicKey
     * @param originatorEncKey
     * @param keyToBeEncrypted
     * @return
     * @throws WSSecurityException
     */

    protected byte[] aesWrapKeyWithDHGeneratedKey(PublicKey recipientPublicKey, PrivateKey originatorEncKey,
                                                  SecretKey keyToBeEncrypted, String keyDerivationMethod, int keyByteSize)
            throws WSSecurityException {
        try {
            String algorithm = originatorEncKey.getAlgorithm();
            // java 11 uses ECDH instead of EC
            algorithm = algorithm.equalsIgnoreCase("EC") ? "ECDH" : algorithm;
            KeyAgreement keyAgreement = KeyAgreement.getInstance(algorithm);
            keyAgreement.init(originatorEncKey);
            keyAgreement.doPhase(recipientPublicKey, true);
            byte[] kek = keyAgreement.generateSecret();
            // derive key from
            if (keyDerivationMethod != null && !keyDerivationMethod.isBlank()) {
                DerivationAlgorithm da = AlgoFactory.getInstance(ConversationConstants.DerivationAlgorithm.CONCAT_KDF);
                kek = da.createKey(kek, null, 0, keyByteSize);
            }

            Cipher wrapCipher = Cipher.getInstance("AESWrap");
            SecretKey wrapSecretKey = new SecretKeySpec(kek, "AES");
            wrapCipher.init(Cipher.WRAP_MODE, wrapSecretKey);
            return wrapCipher.wrap(keyToBeEncrypted);
        } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException
                 | IllegalBlockSizeException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, e);
        }
    }

    protected byte[] encryptSymmetricKeyWithDH(PublicKey encryptingKey, SecretKey keyToBeEncrypted, PrivateKey dhPrivateKey,
                                               String kdfAlgorithm) throws WSSecurityException {
        int keyByteSize = keyToBeEncrypted.getEncoded().length;

        switch (keyEncAlgo) {
            case WSConstants.KEYWRAP_AES128:
                keyByteSize = 128 / 8;
                break;
            case WSConstants.KEYWRAP_AES192:
                keyByteSize = 192 / 8;
                break;
            case WSConstants.KEYWRAP_AES256:
                keyByteSize = 256 / 8;
                break;
        }

        return aesWrapKeyWithDHGeneratedKey(encryptingKey, dhPrivateKey, keyToBeEncrypted, kdfAlgorithm, keyByteSize);
    }


    protected byte[] encryptSymmetricKey(PublicKey encryptingKey, SecretKey keyToBeEncrypted)
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
        LOG.debug("cipher blksize: {}", blockSize);

        try {
            return cipher.wrap(keyToBeEncrypted);
        } catch (IllegalStateException | IllegalBlockSizeException | InvalidKeyException ex) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.FAILED_ENCRYPTION, ex
            );
        }
    }

    /**
     * Add a BinarySecurityToken
     */
    private void addBST(X509Certificate cert) throws WSSecurityException {
        bstToken = new X509Security(getDocument());
        ((X509Security) bstToken).setX509Certificate(cert);

        bstAddedToSecurityHeader = false;
        bstToken.setID(IDGenerator.generateID(null));
        if (addWSUNamespace) {
            bstToken.addWSUNamespace();
        }
    }

    /**
     * Create DOM subtree for <code>xenc:EncryptedKey</code>
     *
     * @param doc the SOAP envelope parent document
     * @param keyTransportAlgo specifies which algorithm to use to encrypt the symmetric key
     * @return an <code>xenc:EncryptedKey</code> element
     */
    private Element createEncryptedKey(Document doc, String keyTransportAlgo) {
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


    protected Element createAgreementMethod(Document doc, String agreementMethod, PublicKey originatorPublicKey,
                                            SecurityTokenReference recipientKeyToken) throws WSSecurityException {
        Element agreementMethodElement =
                doc.createElementNS(
                        WSConstants.ENC_NS, WSConstants.ENC_PREFIX + ":" + WSConstants.AGREEMENT_METHOD_LN);
        agreementMethodElement.setAttributeNS(
                WSConstants.XMLNS_NS, "xmlns:" + WSConstants.ENC11_PREFIX, WSConstants.ENC11_NS
        );

        agreementMethodElement.setAttributeNS(null, WSS4JConstants.ATTR_ALGORITHM, agreementMethod);
        // set KeyDerivationMethodElement
        Element keyDerivationMethodElement = createKeyDerivationMethod(doc, WSS4JConstants.KDF_CONCAT, digestAlgo);
        agreementMethodElement.appendChild(keyDerivationMethodElement);

        // generate OriginatorKeyInfo
        Element originatorKeyInfoElement = createOriginatorKeyElement(doc, originatorPublicKey);
        agreementMethodElement.appendChild(originatorKeyInfoElement);

        // generate RecipientKeyInfo
        Element recipientKeyInfo =
                doc.createElementNS(
                        WSConstants.ENC_NS, WSConstants.ENC_PREFIX + ":" + WSConstants.RECIPIENT_KEY_INFO_LN);
        Element recipientKeyInfoKeyValueElement =
                XMLUtils.createElementInSignatureSpace(doc, Constants._TAG_KEYVALUE);

        recipientKeyInfoKeyValueElement.appendChild(recipientKeyToken.getElement());
        recipientKeyInfo.appendChild(recipientKeyInfoKeyValueElement);
        agreementMethodElement.appendChild(recipientKeyInfo);

        return agreementMethodElement;
    }


    protected Element createKeyDerivationMethod(Document doc, String keyDerivationMethod, String digestAlgorithm) {
        // set KeyDerivationMethodElement
        Element keyDerivationMethodElement =
                doc.createElementNS(
                        WSConstants.ENC11_NS, WSConstants.ENC11_PREFIX + ":" + WSConstants.KEY_DERIVATION_METHOD_LN);
        keyDerivationMethodElement.setAttributeNS(null, WSS4JConstants.ATTR_ALGORITHM, keyDerivationMethod);

        Element concatKDFParams =
                doc.createElementNS(
                        WSConstants.ENC11_NS, WSConstants.ENC11_PREFIX + ":" + WSConstants.CONCAT_KDF_PARAMS_LN);
        concatKDFParams.setAttributeNS(null, WSS4JConstants.ATTR_ALGORITHM_ID, "");
        concatKDFParams.setAttributeNS(null, WSS4JConstants.ATTR_PARTY_UINFO, "");
        concatKDFParams.setAttributeNS(null, WSS4JConstants.ATTR_PARTY_VINFO, "");

        Element digestElement =
                XMLUtils.createElementInSignatureSpace(doc, Constants._TAG_DIGESTMETHOD);
        digestElement.setAttributeNS(null, WSS4JConstants.ATTR_ALGORITHM, digestAlgorithm);

        concatKDFParams.appendChild(digestElement);
        keyDerivationMethodElement.appendChild(concatKDFParams);

        return keyDerivationMethodElement;
    }

    /**
     * Create OriginatorKeyInfo element for ECDH-ES
     * <xenc:OriginatorKeyInfo>
     * <ds:KeyValue>
     * <ds11:ECKeyValue xmlns:ds11="http://www.w3.org/2009/xmldsig11#">
     * <ds11:NamedCurve URI="urn:oid:1.3.101.110"/>
     * <ds11:PublicKey>RU5DT0RFRA==</ds11:PublicKey>
     * </ds11:ECKeyValue>
     * </ds:KeyValue>
     * </xenc:OriginatorKeyInfo>
     *
     * @param doc
     * @param originatorPublicKey
     * @return
     * @throws WSSecurityException
     */
    public Element createOriginatorKeyElement(Document doc, PublicKey originatorPublicKey) throws WSSecurityException {

        Element originatorKeyInfoElement =
                doc.createElementNS(
                        WSConstants.ENC_NS, WSConstants.ENC_PREFIX + ":" + WSConstants.ORIGINATOR_KEY_INFO_LN);

        if (originatorPublicKey instanceof XECPublicKey) {
            Element originatorDerKeyValueElement =
                    XMLUtils.createElementInSignature11Space(doc, WSConstants.DER_ENCODED_KEY_VALUE_LN);
            Text keyText =
                    WSSecurityUtil.createBase64EncodedTextNode(doc, originatorPublicKey.getEncoded());

            originatorDerKeyValueElement.appendChild(keyText);
            originatorKeyInfoElement.appendChild(originatorDerKeyValueElement);
        } else if (originatorPublicKey instanceof ECPublicKey) {
            try {
                DOMKeyInfoFactory keyInfoFactory = new DOMKeyInfoFactory();
                KeyValue keyValue = keyInfoFactory.newKeyValue(originatorPublicKey);

                ((org.apache.jcp.xml.dsig.internal.dom.DOMKeyValue) keyValue).marshal(originatorKeyInfoElement, null, null);


            } catch (KeyException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_ENCRYPTION, e);
            } catch (MarshalException e) {
                throw new RuntimeException(e);
            }
        }



        /*
        Element originatorKeyValueElement =
                XMLUtils.createElementInSignatureSpace(doc, Constants._TAG_KEYVALUE);

        Element originatorECKeyValueElement =
                XMLUtils.createElementInSignature11Space(doc, Constants._TAG_ECKEYVALUE);

        Element namedCurveElement =
                XMLUtils.createElementInSignature11Space(doc, WSS4JConstants.NAMED_CURVE_LN);
        String keyAlgorithm = originatorPublicKey.getAlgorithm();

        String keyOIDValue = KEY_OID_PATTERN.matcher(keyAlgorithm).matches() ? keyAlgorithm :
                getOIDForJCEAlgorithm(originatorPublicKey);

        namedCurveElement.setAttributeNS(null, WSS4JConstants.ATTR_URI, "urn:oid:" + keyOIDValue);
        Element publicKeyElement =
                XMLUtils.createElementInSignature11Space(doc, WSS4JConstants.PUBLIC_KEY_LN);
        Text keyText =
                WSSecurityUtil.createBase64EncodedTextNode(doc, originatorPublicKey.getEncoded());

        publicKeyElement.appendChild(keyText);
        originatorECKeyValueElement.appendChild(namedCurveElement);
        originatorECKeyValueElement.appendChild(publicKeyElement);
        originatorKeyValueElement.appendChild(originatorECKeyValueElement);
        originatorKeyInfoElement.appendChild(originatorKeyValueElement);
         */

        return originatorKeyInfoElement;
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

    public String getKeyAgreementMethod() {
        return keyAgreementMethod;
    }

    public void setKeyAgreementMethod(String keyAgreementMethod) {
        this.keyAgreementMethod = keyAgreementMethod;
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
     * @param encKeyId The encKeyId to set.
     */
    public void setEncKeyId(String encKeyId) {
        this.encKeyId = encKeyId;
    }

    public boolean isCertSet() {
        return useThisCert != null;
    }

    public void setCustomEKTokenValueType(String customEKTokenValueType) {
        this.customEKTokenValueType = customEKTokenValueType;
    }

    public void setCustomEKTokenId(String customEKTokenId) {
        this.customEKTokenId = customEKTokenId;
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

    protected void setEncryptedKeySHA1(byte[] encryptedEphemeralKey) throws WSSecurityException {
        byte[] encodedBytes = KeyUtils.generateDigest(encryptedEphemeralKey);
        encryptedKeySHA1 = XMLUtils.encodeToString(encodedBytes);
    }

    public String getEncryptedKeySHA1() {
        return encryptedKeySHA1;
    }
}
