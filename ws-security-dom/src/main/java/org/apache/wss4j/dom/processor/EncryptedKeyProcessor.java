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

package org.apache.wss4j.dom.processor;

import org.apache.wss4j.common.WSS4JConstants;
import org.apache.wss4j.common.bsp.BSPEnforcer;
import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.crypto.AlgorithmSuite;
import org.apache.wss4j.common.crypto.AlgorithmSuiteValidator;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.derivedKey.ConcatKDF;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.token.DOMX509IssuerSerial;
import org.apache.wss4j.common.token.SecurityTokenReference;
import org.apache.wss4j.common.util.KeyUtils;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSDataRef;
import org.apache.wss4j.dom.WSDocInfo;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.str.EncryptedKeySTRParser;
import org.apache.wss4j.dom.str.STRParser;
import org.apache.wss4j.dom.str.STRParserParameters;
import org.apache.wss4j.dom.str.STRParserResult;
import org.apache.wss4j.dom.util.EncryptionUtils;
import org.apache.wss4j.dom.util.SignatureUtils;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.apache.wss4j.dom.util.X509Util;
import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.encryption.XMLCipher;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

public class EncryptedKeyProcessor implements Processor {
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(EncryptedKeyProcessor.class);

    private final Provider provider;

    public EncryptedKeyProcessor() {
        this(null);
    }

    public EncryptedKeyProcessor(Provider provider) {
        this.provider = provider;
    }

    public List<WSSecurityEngineResult> handleToken(
        Element elem,
        RequestData data
    ) throws WSSecurityException {
        return handleToken(elem, data, data.getAlgorithmSuite());
    }

    public List<WSSecurityEngineResult> handleToken(
        Element elem,
        RequestData data,
        AlgorithmSuite algorithmSuite
    ) throws WSSecurityException {
        LOG.debug("Found encrypted key element");

        // See if this key has already been processed. If so then just return the result
        String id = elem.getAttributeNS(null, "Id");
        if (id.length() != 0) {
             WSSecurityEngineResult result = data.getWsDocInfo().getResult(id);
             if (result != null
                 && WSConstants.ENCR == (Integer)result.get(WSSecurityEngineResult.TAG_ACTION)
             ) {
                 return Collections.singletonList(result);
             }
        }

        if (data.getCallbackHandler() == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "noCallback");
        }
        //
        // lookup xenc:EncryptionMethod, get the Algorithm attribute to determine
        // how the key was encrypted. Then check if we support the algorithm
        //
        String encryptedKeyTransportMethod = X509Util.getEncAlgo(elem);
        if (encryptedKeyTransportMethod == null) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.UNSUPPORTED_ALGORITHM, "noEncAlgo"
            );
        }
        if (WSConstants.KEYTRANSPORT_RSA15.equals(encryptedKeyTransportMethod)
            && !data.isAllowRSA15KeyTransportAlgorithm()
            && (algorithmSuite == null
              || !algorithmSuite.getKeyWrapAlgorithms().contains(WSConstants.KEYTRANSPORT_RSA15))) {
            LOG.debug(
                "The Key transport method does not match the requirement"
            );
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY);
        }

        Element keyInfoChildElement = getKeyInfoChildElement(elem, data);
        boolean isDHKeyWrap = isDiffieHellmanKeyWrap(keyInfoChildElement);

        // Check BSP Compliance
        checkBSPCompliance(elem, encryptedKeyTransportMethod, isDHKeyWrap, data.getBSPEnforcer());

        //
        // Now lookup CipherValue.
        //
        Element xencCipherValue = EncryptionUtils.getCipherValueFromEncryptedData(elem);
        if (xencCipherValue == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, "noCipher");
        }

        Element refList =
                XMLUtils.getDirectChildElement(elem, "ReferenceList", WSConstants.ENC_NS);

        // Get the key bytes from CipherValue directly or via an attachment
        String xopUri = EncryptionUtils.getXOPURIFromCipherValue(xencCipherValue);
        byte[] encryptedEphemeralKey;
        if (xopUri != null && xopUri.startsWith("cid:")) {
            encryptedEphemeralKey = WSSecurityUtil.getBytesFromAttachment(xopUri, data);
        } else {
            encryptedEphemeralKey = EncryptionUtils.getDecodedBase64EncodedData(xencCipherValue);
        }

        PublicKey originatorPublicKey = null;
        PublicKey publicKey = null;
        X509Certificate[] certs = null;
        STRParser.REFERENCE_TYPE referenceType = null;
        boolean symmetricKeyWrap = isSymmetricKeyWrap(encryptedKeyTransportMethod);
        if (isDHKeyWrap) {
            // get originator key value
            originatorPublicKey = getDHOriginatorPublicKey(keyInfoChildElement, data);
            // get recipient key value
            CertificateResult certificateResult = getDHReceiverPublicKey(keyInfoChildElement, data);
            certs = certificateResult.getCerts();
            publicKey = certificateResult.getPublicKey();
        } else if (!symmetricKeyWrap) {
            CertificateResult certificateResult = getPublicKey(keyInfoChildElement, data);
            certs = certificateResult.getCerts();
            publicKey = certificateResult.getPublicKey();
            referenceType = certificateResult.getCertificatesReferenceType();
        }

        // Check for compliance against the defined AlgorithmSuite
        if (algorithmSuite != null) {
            AlgorithmSuiteValidator algorithmSuiteValidator = new
                AlgorithmSuiteValidator(algorithmSuite);

            if (!symmetricKeyWrap) {
                algorithmSuiteValidator.checkAsymmetricKeyLength(publicKey);
            }
            algorithmSuiteValidator.checkEncryptionKeyWrapAlgorithm(
                encryptedKeyTransportMethod
            );
        }

        byte[] decryptedBytes;
        if (isDHKeyWrap) {
            PrivateKey privateKey = getPrivateKey(data, certs, publicKey);
            Element keyDerivationMethodElement = XMLUtils.getDirectChildElement(
                    keyInfoChildElement, WSS4JConstants.KEY_DERIVATION_METHOD_LN, WSConstants.ENC11_NS);

            decryptedBytes = getUnwrapDHKey(data, keyDerivationMethodElement, privateKey, originatorPublicKey,
                    encryptedKeyTransportMethod, encryptedEphemeralKey);
        } else if (symmetricKeyWrap) {
            decryptedBytes = getSymmetricDecryptedBytes(data, data.getWsDocInfo(), keyInfoChildElement, refList);
        } else {
            PrivateKey privateKey = getPrivateKey(data, certs, publicKey);
            decryptedBytes = getAsymmetricDecryptedBytes(data, data.getWsDocInfo(), encryptedKeyTransportMethod,
                                                         encryptedEphemeralKey, refList,
                                                         elem, privateKey);
        }

        List<WSDataRef> dataRefs = decryptDataRefs(refList, data.getWsDocInfo(), decryptedBytes, data);

        WSSecurityEngineResult result = new WSSecurityEngineResult(
                WSConstants.ENCR,
                decryptedBytes,
                encryptedEphemeralKey,
                dataRefs,
                certs
            );
        result.put(
            WSSecurityEngineResult.TAG_ENCRYPTED_KEY_TRANSPORT_METHOD,
            encryptedKeyTransportMethod
        );
        result.put(WSSecurityEngineResult.TAG_TOKEN_ELEMENT, elem);
        String tokenId = elem.getAttributeNS(null, "Id");
        if (tokenId.length() != 0) {
            result.put(WSSecurityEngineResult.TAG_ID, tokenId);
        }
        if (referenceType != null) {
            result.put(WSSecurityEngineResult.TAG_X509_REFERENCE_TYPE, referenceType);
        }
        if (publicKey != null) {
            result.put(WSSecurityEngineResult.TAG_PUBLIC_KEY, publicKey);
        }
        data.getWsDocInfo().addResult(result);
        data.getWsDocInfo().addTokenElement(elem);
        return Collections.singletonList(result);
    }

    public PublicKey getDHOriginatorPublicKey(Element keyInfoChildElement, RequestData data) throws WSSecurityException {

        // get sender key value
        Element originatorKeyInfoElement =
                XMLUtils.getDirectChildElement(
                        keyInfoChildElement, WSS4JConstants.ORIGINATOR_KEY_INFO_LN, WSConstants.ENC_NS
                );
        Element originatorKeyValueElement =
                XMLUtils.getDirectChildElement(
                        originatorKeyInfoElement, WSS4JConstants.KEYVALUE_LN, WSConstants.SIG_NS
                );


        Element originatorPublicKeyElement;
        if (originatorKeyValueElement == null) {
            originatorPublicKeyElement =
                    XMLUtils.getDirectChildElement(
                            originatorKeyInfoElement, WSS4JConstants.DER_ENCODED_KEY_VALUE_LN, WSConstants.SIG11_NS
                    );
            byte[] pkBuff = Base64.getDecoder().decode(XMLUtils.getElementText(originatorPublicKeyElement));
            PublicKey originatorPublicKey = parsePublicKey(pkBuff, "EC");
            if (originatorPublicKey == null) {
                originatorPublicKey = parsePublicKey(pkBuff, "XDH");
            }
            if (originatorPublicKey == null) {
                throw new WSSecurityException(
                        WSSecurityException.ErrorCode.FAILURE,
                        "Unknown Originator Key Type");
            }
            return originatorPublicKey;
        } else {
            originatorKeyInfoElement.removeChild(originatorKeyValueElement);
            Element keyInfoElement =
                    originatorKeyValueElement.getOwnerDocument().createElementNS(
                            WSConstants.SIG_NS, WSConstants.SIG_PREFIX + ":" + WSConstants.KEYINFO_LN);
            keyInfoElement.appendChild(originatorKeyValueElement);
            CertificateResult result = getPublicKey(originatorKeyValueElement, data);
            return result.getPublicKey();
        }
    }

    public PublicKey parsePublicKey(byte[] derEncodedPK, String algorithm) {
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(derEncodedPK);
            KeyFactory factory = KeyFactory.getInstance(algorithm);
            return factory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            LOG.debug("Error parsing public key", e);
        }
        return null;
    }

    private CertificateResult getDHReceiverPublicKey(Element keyInfoChildElement, RequestData data)
            throws WSSecurityException {
        // get receiver key value
        Element recipientKeyInfo =
                XMLUtils.getDirectChildElement(
                        keyInfoChildElement, WSConstants.RECIPIENT_KEY_INFO_LN, WSConstants.ENC_NS
                );
        Element recipientKeyValue =
                XMLUtils.getDirectChildElement(
                        recipientKeyInfo, WSConstants.KEYVALUE_LN, WSConstants.SIG_NS
                );
        Element keyInfoElement = getOnlyChildElement(recipientKeyValue, data);
        return getPublicKey(keyInfoElement, data);
    }

    /**
     * Resolve the KeyInfoType child element to locate the public key (with the X509Certificate chain if given )
     * to use to decrypt the EncryptedKey.
     *
     * @param keyValueElement The element to get the child element from
     * @param data            The RequestData context
     * @return The CertificateResult object containing the public key and optionally X509Certificate chain
     * @throws WSSecurityException an error occurred when trying to resolve the key info
     */
    private CertificateResult getPublicKey(Element keyValueElement, RequestData data) throws WSSecurityException {
        CertificateResult.Builder builder = CertificateResult.Builder.create();

        if (SecurityTokenReference.SECURITY_TOKEN_REFERENCE.equals(keyValueElement.getLocalName())
                && WSConstants.WSSE_NS.equals(keyValueElement.getNamespaceURI())) {
            STRParserParameters parameters = new STRParserParameters();
            parameters.setData(data);
            parameters.setStrElement(keyValueElement);

            STRParser strParser = new EncryptedKeySTRParser();
            STRParserResult result = strParser.parseSecurityTokenReference(parameters);
            builder.certificates(result.getCertificates());
            builder.publicKey(result.getPublicKey());
            builder.certificatesReferenceType(result.getCertificatesReferenceType());
        } else {
            X509Certificate[] certs = getCertificatesFromX509Data(keyValueElement, data);
            builder.certificates(certs);
            if (certs == null || certs.length == 0) {
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

                PublicKey publicKey = X509Util.parseKeyValue((Element) keyValueElement.getParentNode(),
                        signatureFactory);
                builder.publicKey(publicKey);
            }
        }
        return builder.build();
    }

    private PrivateKey getPrivateKey(
        RequestData data, X509Certificate[] certs, PublicKey publicKey
    ) throws WSSecurityException {
        try {
            if (certs != null && certs.length > 0) {
                return data.getDecCrypto().getPrivateKey(certs[0], data.getCallbackHandler());
            }
            return data.getDecCrypto().getPrivateKey(publicKey, data.getCallbackHandler());
        } catch (WSSecurityException ex) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, ex);
        }
    }


    /**
     * Method uses Diffie-Hellman algorithm (ECDH or XDH) to generate a shared secret key. The shared secret key is used to
     * derive encrypted key to decrypt the EncryptedKey value using wrapped EAS.
     *
     * @param data                        The RequestData context
     * @param receiverPK                  The receiver's private key
     * @param originatorPublicKey         The originator's public key
     * @param encryptedKeyTransportMethod The encryption algorithm used to encrypt the EncryptedKey value
     * @param encryptedEphemeralKey       The EncryptedKey value
     * @return The decrypted EncryptedKey value
     * @throws WSSecurityException an error occurred when trying to decrypt the EncryptedKey value
     */
    private byte[] getUnwrapDHKey(RequestData data, Element keyDerivationMethodElement, PrivateKey receiverPK,
                                  PublicKey originatorPublicKey, String encryptedKeyTransportMethod, byte[] encryptedEphemeralKey)
            throws WSSecurityException {

        try {
            String keyAgreementAlg = receiverPK.getAlgorithm().equalsIgnoreCase("EC") ? "ECDH" : "XDH";
            String cryptoProvider = data.getDecCrypto().getCryptoProvider();
            KeyAgreement keyAgreement = cryptoProvider != null
                    ? KeyAgreement.getInstance(keyAgreementAlg, cryptoProvider) : KeyAgreement.getInstance(keyAgreementAlg);
            keyAgreement.init(receiverPK);
            keyAgreement.doPhase(originatorPublicKey, true);
            final byte[] exchangedSharedSecretKey = keyAgreement.generateSecret();
            final byte[] derivedKek = deriveKeyEncryptionKey(exchangedSharedSecretKey, keyDerivationMethodElement,
                    encryptedKeyTransportMethod);

            Cipher unwrapCipher = KeyUtils.getCipherInstance(encryptedKeyTransportMethod, cryptoProvider);
            SecretKey unwrapSecretKey = new SecretKeySpec(derivedKek, "AES");
            unwrapCipher.init(Cipher.UNWRAP_MODE, unwrapSecretKey);
            final Key aes = unwrapCipher.unwrap(encryptedEphemeralKey, "AES", Cipher.SECRET_KEY);
            return aes.getEncoded();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.UNSUPPORTED_ALGORITHM, e);
        } catch (InvalidKeyException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, e);
        }
    }

    public byte[] deriveKeyEncryptionKey(byte[] sharedSecret, Element keyDerivationMethodElement, String keyWrapAlgorithm)
            throws WSSecurityException {
        int iKeySize = getKeyByteSizeFromKeyWrapAlgorithm(keyWrapAlgorithm);
        String keyDerivationMethod = keyDerivationMethodElement.getAttributeNS(null, "Algorithm");
        if (!WSS4JConstants.KDF_CONCAT.equals(keyDerivationMethod)) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.UNSUPPORTED_ALGORITHM, "unknownAlgorithm",
                    new Object[]{keyWrapAlgorithm});
        }
        Element concatKDFParams = XMLUtils.getDirectChildElement(keyDerivationMethodElement,
                WSS4JConstants.CONCAT_KDF_PARAMS_LN, WSS4JConstants.ENC11_NS);
        if (concatKDFParams == null) {
            LOG.debug("Missing ConcatKDFParams for key derivation with algorithm [{}]", keyDerivationMethod);
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "errorInKeyDerivation");
        }
        // get parameters
        String digestAlgorithm = EncryptionUtils.getAlgorithmFromChildDigestMethod(concatKDFParams);
        if (digestAlgorithm == null) {
            LOG.debug("Missing ConcatKDFParams Digest algorithm for key derivation with algorithm [{}]", keyDerivationMethod);
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "errorInKeyDerivation");
        }
        String algorithmID = concatKDFParams.getAttributeNS(null, WSS4JConstants.ATTR_ALGORITHM_ID);
        String partyUInfo = concatKDFParams.getAttributeNS(null, WSS4JConstants.ATTR_PARTY_UINFO);
        String partyVInfo = concatKDFParams.getAttributeNS(null, WSS4JConstants.ATTR_PARTY_VINFO);
        String suppPubInfo = concatKDFParams.getAttributeNS(null, WSS4JConstants.ATTR_SUPP_PUBINFO);
        String suppPrivInfo = concatKDFParams.getAttributeNS(null, WSS4JConstants.ATTR_SUPP_PRIVINFO);

        ConcatKDF concatKDF = new ConcatKDF(digestAlgorithm);
        return concatKDF.createKey(sharedSecret, algorithmID, partyUInfo, partyVInfo, suppPubInfo, suppPrivInfo, iKeySize);
    }

    public int getKeyByteSizeFromKeyWrapAlgorithm(String keyWrapAlgorithm) throws WSSecurityException {
        switch (keyWrapAlgorithm) {
            case XMLCipher.AES_128_KeyWrap:
                return 128 / 8;
            case XMLCipher.AES_192_KeyWrap:
                return 192 / 8;
            case XMLCipher.AES_256_KeyWrap:
                return 256 / 8;
            default:
                throw new WSSecurityException(
                        WSSecurityException.ErrorCode.UNSUPPORTED_ALGORITHM,
                        "unknownAlgorithm",
                        new Object[]{keyWrapAlgorithm}
                );
        }
    }

    private static byte[] getSymmetricDecryptedBytes(
        RequestData data,
        WSDocInfo wsDocInfo,
        Element keyInfoChildElement,
        Element refList
    ) throws WSSecurityException {
        // Get the (first) encryption algorithm
        String uri = getFirstDataRefURI(refList);
        String algorithmURI = null;
        if (uri != null) {
            Element ee =
                EncryptionUtils.findEncryptedDataElement(wsDocInfo, uri);
            algorithmURI = X509Util.getEncAlgo(ee);
        }
        return X509Util.getSecretKey(keyInfoChildElement, algorithmURI, data.getCallbackHandler());
    }

    private static byte[] getAsymmetricDecryptedBytes(
        RequestData data,
        WSDocInfo wsDocInfo,
        String encryptedKeyTransportMethod,
        byte[] encryptedEphemeralKey,
        Element refList,
        Element encryptedKeyElement,
        PrivateKey privateKey
    ) throws WSSecurityException {
        if (data.getDecCrypto() == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "noDecCryptoFile");
        }
        String cryptoProvider = data.getDecCrypto().getCryptoProvider();
        Cipher cipher = KeyUtils.getCipherInstance(encryptedKeyTransportMethod, cryptoProvider);
        try {
            OAEPParameterSpec oaepParameterSpec = null;
            if (WSConstants.KEYTRANSPORT_RSAOAEP.equals(encryptedKeyTransportMethod)
                || WSConstants.KEYTRANSPORT_RSAOAEP_XENC11.equals(encryptedKeyTransportMethod)) {
                // Get the DigestMethod if it exists
                String digestAlgorithm = EncryptionUtils.getDigestAlgorithm(encryptedKeyElement);
                String jceDigestAlgorithm = "SHA-1";
                if (digestAlgorithm != null && digestAlgorithm.length() != 0) {
                    jceDigestAlgorithm = JCEMapper.translateURItoJCEID(digestAlgorithm);
                }

                MGF1ParameterSpec mgfParameterSpec = new MGF1ParameterSpec("SHA-1");
                if (WSConstants.KEYTRANSPORT_RSAOAEP_XENC11.equals(encryptedKeyTransportMethod)) {
                    String mgfAlgorithm = EncryptionUtils.getMGFAlgorithm(encryptedKeyElement);
                    if (WSConstants.MGF_SHA224.equals(mgfAlgorithm)) {
                        mgfParameterSpec = new MGF1ParameterSpec("SHA-224");
                    } else if (WSConstants.MGF_SHA256.equals(mgfAlgorithm)) {
                        mgfParameterSpec = new MGF1ParameterSpec("SHA-256");
                    } else if (WSConstants.MGF_SHA384.equals(mgfAlgorithm)) {
                        mgfParameterSpec = new MGF1ParameterSpec("SHA-384");
                    } else if (WSConstants.MGF_SHA512.equals(mgfAlgorithm)) {
                        mgfParameterSpec = new MGF1ParameterSpec("SHA-512");
                    }
                }

                PSource.PSpecified pSource = PSource.PSpecified.DEFAULT;
                byte[] pSourceBytes = EncryptionUtils.getPSource(encryptedKeyElement);
                if (pSourceBytes != null && pSourceBytes.length > 0) {
                    pSource = new PSource.PSpecified(pSourceBytes);
                }

                oaepParameterSpec =
                    new OAEPParameterSpec(
                        jceDigestAlgorithm, "MGF1", mgfParameterSpec, pSource
                    );
            }

            if (oaepParameterSpec == null) {
                cipher.init(Cipher.UNWRAP_MODE, privateKey);
            } else {
                cipher.init(Cipher.UNWRAP_MODE, privateKey, oaepParameterSpec);
            }
        } catch (Exception ex) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, ex);
        }

        try {
            String keyAlgorithm = JCEMapper.translateURItoJCEID(encryptedKeyTransportMethod);
            return cipher.unwrap(encryptedEphemeralKey, keyAlgorithm, Cipher.SECRET_KEY).getEncoded();
        } catch (IllegalStateException ex) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, ex);
        } catch (Exception ex) {
            return getRandomKey(refList, wsDocInfo);
        }
    }

    private static boolean isSymmetricKeyWrap(String transportAlgorithm) {
        return XMLCipher.AES_128_KeyWrap.equals(transportAlgorithm)
            || XMLCipher.AES_192_KeyWrap.equals(transportAlgorithm)
            || XMLCipher.AES_256_KeyWrap.equals(transportAlgorithm)
            || XMLCipher.TRIPLEDES_KeyWrap.equals(transportAlgorithm)
            || XMLCipher.CAMELLIA_128_KeyWrap.equals(transportAlgorithm)
            || XMLCipher.CAMELLIA_192_KeyWrap.equals(transportAlgorithm)
            || XMLCipher.CAMELLIA_256_KeyWrap.equals(transportAlgorithm)
            || XMLCipher.SEED_128_KeyWrap.equals(transportAlgorithm);
    }

    /**
     * if keInfo element contains AgreementMethod element then check it is supported EC Diffie-Hellman key agreement algorithm
     *
     * @param keyInfoChildElement The KeyInfo child element
     * @return true if AgreementMethod element is present and DH algorithm supported and false if AgreementMethod element is not present
     * @throws WSSecurityException if AgreementMethod element is present but DH algorithm is not supported
     */
    private boolean isDiffieHellmanKeyWrap(Element keyInfoChildElement) throws WSSecurityException {
        if (WSS4JConstants.AGREEMENT_METHOD_LN.equals(keyInfoChildElement.getLocalName())
                && WSConstants.ENC_NS.equals(keyInfoChildElement.getNamespaceURI())) {
            String algorithmURI = keyInfoChildElement.getAttributeNS(null, "Algorithm");
            // Only ECDH_ES is supported for AgreementMethod
            if (!WSConstants.AGREEMENT_METHOD_ECDH_ES.equals(algorithmURI)) {
                throw new WSSecurityException(
                        WSSecurityException.ErrorCode.UNSUPPORTED_ALGORITHM,
                        "unknownAlgorithm", new Object[]{algorithmURI});
            }
            return true;
        }
        return false;
    }

    /**
     * Generates a random secret key using the algorithm specified in the
     * first DataReference URI
     */
    private static byte[] getRandomKey(Element refList, WSDocInfo wsDocInfo) throws WSSecurityException {
        try {
            String alg = "AES";
            int size = 16;
            String uri = getFirstDataRefURI(refList);

            if (uri != null) {
                Element ee =
                    EncryptionUtils.findEncryptedDataElement(wsDocInfo, uri);
                String algorithmURI = X509Util.getEncAlgo(ee);
                alg = JCEMapper.getJCEKeyAlgorithmFromURI(algorithmURI);
                size = KeyUtils.getKeyLength(algorithmURI);
            }
            KeyGenerator kgen = KeyGenerator.getInstance(alg);
            kgen.init(size * 8);
            SecretKey k = kgen.generateKey();
            return k.getEncoded();
        } catch (Throwable ex) {
            // Fallback to just using AES to avoid attacks on EncryptedData algorithms
            try {
                KeyGenerator kgen = KeyGenerator.getInstance("AES");
                kgen.init(128);
                SecretKey k = kgen.generateKey();
                return k.getEncoded();
            } catch (NoSuchAlgorithmException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, e);
            }
        }
    }

    private static String getFirstDataRefURI(Element refList) {
        // Lookup the references that are encrypted with this key
        if (refList != null) {
            for (Node node = refList.getFirstChild(); node != null; node = node.getNextSibling()) {
                if (Node.ELEMENT_NODE == node.getNodeType()
                        && WSConstants.ENC_NS.equals(node.getNamespaceURI())
                        && "DataReference".equals(node.getLocalName())) {
                    String dataRefURI = ((Element) node).getAttributeNS(null, "URI");
                    return XMLUtils.getIDFromReference(dataRefURI);
                }
            }
        }
        return null;
    }

    private Element getKeyInfoChildElement(
        Element xencEncryptedKey, RequestData data
    ) throws WSSecurityException {
        Element keyInfo =
            XMLUtils.getDirectChildElement(xencEncryptedKey, "KeyInfo", WSConstants.SIG_NS);
        if (keyInfo != null) {
            return getOnlyChildElement(keyInfo, data);
        } else {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, "noKeyinfo");
        }
    }

    private Element getOnlyChildElement(Element parent, RequestData data) throws WSSecurityException {
        Element strElement = null;

        int result = 0;
        Node node = parent.getFirstChild();
        while (node != null) {
            if (Node.ELEMENT_NODE == node.getNodeType()) {
                result++;
                strElement = (Element) node;
            }
            node = node.getNextSibling();
        }
        if (result != 1) {
            data.getBSPEnforcer().handleBSPRule(BSPRule.R5424);
        }

        if (strElement == null) {
            throw new WSSecurityException(
                    WSSecurityException.ErrorCode.INVALID_SECURITY, "noSecTokRef"
            );
        }
        return strElement;
    }

    private X509Certificate[] getCertificatesFromX509Data(
        Element keyInfoChildElement,
        RequestData data
    ) throws WSSecurityException {

        if (WSConstants.SIG_NS.equals(keyInfoChildElement.getNamespaceURI())
            && WSConstants.X509_DATA_LN.equals(keyInfoChildElement.getLocalName())) {
            data.getBSPEnforcer().handleBSPRule(BSPRule.R5426);

            Element x509Child = getFirstElement(keyInfoChildElement);

            if (x509Child != null && WSConstants.SIG_NS.equals(x509Child.getNamespaceURI())) {
                if (WSConstants.X509_ISSUER_SERIAL_LN.equals(x509Child.getLocalName())) {
                    DOMX509IssuerSerial issuerSerial = new DOMX509IssuerSerial(x509Child);
                    CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ISSUER_SERIAL);
                    cryptoType.setIssuerSerial(issuerSerial.getIssuer(), issuerSerial.getSerialNumber());
                    return data.getDecCrypto().getX509Certificates(cryptoType);
                } else if (WSConstants.X509_CERT_LN.equals(x509Child.getLocalName())) {
                    byte[] token = EncryptionUtils.getDecodedBase64EncodedData(x509Child);
                    if (token == null || token.length == 0) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "invalidCertData",
                                                      new Object[] {"0"});
                    }
                    try (InputStream in = new ByteArrayInputStream(token)) {
                        X509Certificate cert = data.getDecCrypto().loadCertificate(in);
                        if (cert != null) {
                            return new X509Certificate[]{cert};
                        }
                    } catch (IOException e) {
                        throw new WSSecurityException(
                            WSSecurityException.ErrorCode.SECURITY_TOKEN_UNAVAILABLE, e, "parseError"
                        );
                    }
                }
            }
        }

        return new X509Certificate[0];
    }

    private Element getFirstElement(Element element) {
        for (Node currentChild = element.getFirstChild();
             currentChild != null;
             currentChild = currentChild.getNextSibling()
        ) {
            if (Node.ELEMENT_NODE == currentChild.getNodeType()) {
                return (Element) currentChild;
            }
        }
        return null;
    }

    /**
     * Decrypt all data references
     */
    protected List<WSDataRef> decryptDataRefs(Element refList, WSDocInfo docInfo,
                                            byte[] decryptedBytes, RequestData data
    ) throws WSSecurityException {
        //
        // At this point we have the decrypted session (symmetric) key. According
        // to W3C XML-Enc this key is used to decrypt _any_ references contained in
        // the reference list
        if (refList == null) {
            return Collections.emptyList();
        }

        List<WSDataRef> dataRefs = new ArrayList<>();
        for (Node node = refList.getFirstChild(); node != null; node = node.getNextSibling()) {
            if (Node.ELEMENT_NODE == node.getNodeType()
                    && WSConstants.ENC_NS.equals(node.getNamespaceURI())
                    && "DataReference".equals(node.getLocalName())) {
                String dataRefURI = ((Element) node).getAttributeNS(null, "URI");
                dataRefURI = XMLUtils.getIDFromReference(dataRefURI);

                WSDataRef dataRef =
                    decryptDataRef(refList.getOwnerDocument(), dataRefURI, docInfo, decryptedBytes, data);
                dataRefs.add(dataRef);
            }
        }

        return dataRefs;
    }

    /**
     * Decrypt an EncryptedData element referenced by dataRefURI
     */
    protected WSDataRef decryptDataRef(
        Document doc,
        String dataRefURI,
        WSDocInfo docInfo,
        byte[] decryptedData,
        RequestData data
    ) throws WSSecurityException {
        LOG.debug("found data reference: {}", dataRefURI);
        //
        // Find the encrypted data element referenced by dataRefURI
        //
        Element encryptedDataElement =
            EncryptionUtils.findEncryptedDataElement(docInfo, dataRefURI);
        if (encryptedDataElement != null && data.isRequireSignedEncryptedDataElements()) {
            List<WSSecurityEngineResult> signedResults =
                docInfo.getResultsByTag(WSConstants.SIGN);
            SignatureUtils.verifySignedElement(encryptedDataElement, signedResults);
        }
        //
        // Prepare the SecretKey object to decrypt EncryptedData
        //
        String symEncAlgo = X509Util.getEncAlgo(encryptedDataElement);

        // EncryptionAlgorithm cannot be null
        if (symEncAlgo == null) {
            LOG.warn("No encryption algorithm was specified in the request");
            throw new WSSecurityException(WSSecurityException.ErrorCode.UNSUPPORTED_ALGORITHM, "badEncAlgo",
                                          new Object[] {null});

        }
        // EncryptionAlgorithm must be 3DES, or AES128, or AES256
        if (!WSConstants.TRIPLE_DES.equals(symEncAlgo)
            && !WSConstants.AES_128.equals(symEncAlgo)
            && !WSConstants.AES_128_GCM.equals(symEncAlgo)
            && !WSConstants.AES_256.equals(symEncAlgo)
            && !WSConstants.AES_256_GCM.equals(symEncAlgo)) {
            data.getBSPEnforcer().handleBSPRule(BSPRule.R5620);
        }

        SecretKey symmetricKey = null;
        try {
            symmetricKey = KeyUtils.prepareSecretKey(symEncAlgo, decryptedData);
        } catch (IllegalArgumentException ex) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.UNSUPPORTED_ALGORITHM, ex, "badEncAlgo",
                new Object[] {symEncAlgo});
        }

        // Check for compliance against the defined AlgorithmSuite
        AlgorithmSuite algorithmSuite = data.getAlgorithmSuite();
        if (algorithmSuite != null) {
            AlgorithmSuiteValidator algorithmSuiteValidator = new
                AlgorithmSuiteValidator(algorithmSuite);

            algorithmSuiteValidator.checkSymmetricKeyLength(symmetricKey.getEncoded().length);
            algorithmSuiteValidator.checkSymmetricEncryptionAlgorithm(symEncAlgo);
        }

        return EncryptionUtils.decryptEncryptedData(
            doc, dataRefURI, encryptedDataElement, symmetricKey, symEncAlgo, data.getAttachmentCallbackHandler(),
            data.getEncryptionSerializer()
        );
    }

    /**
     * A method to check that the EncryptedKey is compliant with the BSP spec.
     * @throws WSSecurityException
     */
    private void checkBSPCompliance(
            Element elem,
            String encAlgo,
            boolean useKeyWrap,
            BSPEnforcer bspEnforcer
    ) throws WSSecurityException {
        String attribute = elem.getAttributeNS(null, "Type");
        if (attribute != null && attribute.length() != 0) {
            bspEnforcer.handleBSPRule(BSPRule.R3209);
        }
        attribute = elem.getAttributeNS(null, "MimeType");
        if (attribute != null && attribute.length() != 0) {
            bspEnforcer.handleBSPRule(BSPRule.R5622);
        }
        attribute = elem.getAttributeNS(null, "Encoding");
        if (attribute != null && attribute.length() != 0) {
            bspEnforcer.handleBSPRule(BSPRule.R5623);
        }
        attribute = elem.getAttributeNS(null, "Recipient");
        if (attribute != null && attribute.length() != 0) {
            bspEnforcer.handleBSPRule(BSPRule.R5602);
        }

        // EncryptionAlgorithm must be RSA15,RSAOEP, KW-AES128", KW-AES256 or KEYWRAP_TRIPLEDES".
        if (!(WSConstants.KEYTRANSPORT_RSA15.equals(encAlgo)
                || WSConstants.KEYTRANSPORT_RSAOAEP.equals(encAlgo)
                || WSConstants.KEYTRANSPORT_RSAOAEP_XENC11.equals(encAlgo)
                || WSConstants.KEYWRAP_AES128.equals(encAlgo)
                || WSConstants.KEYWRAP_AES256.equals(encAlgo)
                || WSConstants.KEYWRAP_TRIPLEDES.equals(encAlgo))) {
            bspEnforcer.handleBSPRule(BSPRule.R5626);
        }
        if (useKeyWrap) {
            if (!(WSConstants.KEYWRAP_AES128.equals(encAlgo)
                    || WSConstants.KEYWRAP_AES256.equals(encAlgo)
                    || WSConstants.KEYWRAP_TRIPLEDES.equals(encAlgo))) {
                bspEnforcer.handleBSPRule(BSPRule.R5625);
            }
        } else {
            // EncryptionAlgorithm must be RSA15, or RSAOEP.
            if (!(WSConstants.KEYTRANSPORT_RSA15.equals(encAlgo)
                    || WSConstants.KEYTRANSPORT_RSAOAEP.equals(encAlgo)
                    || WSConstants.KEYTRANSPORT_RSAOAEP_XENC11.equals(encAlgo))) {
                bspEnforcer.handleBSPRule(BSPRule.R5621);
            }
        }
    }

}
