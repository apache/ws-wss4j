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

import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.XMLSignContext;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.ExcC14NParameterSpec;

import org.apache.wss4j.api.dom.WSEncryptionPart;
import org.apache.wss4j.common.WSS4JConstants;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.crypto.DERDecoder;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.api.dom.token.BinarySecurity;
import org.apache.wss4j.api.dom.token.DOMX509Data;
import org.apache.wss4j.api.dom.token.DOMX509IssuerSerial;
import org.apache.wss4j.api.dom.token.PKIPathSecurity;
import org.apache.wss4j.api.dom.token.Reference;
import org.apache.wss4j.api.dom.token.SecurityTokenReference;
import org.apache.wss4j.api.dom.token.X509Security;
import org.apache.wss4j.common.util.AttachmentUtils;
import org.apache.wss4j.common.util.KeyUtils;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.api.dom.WSConstants;
import org.apache.wss4j.api.dom.WSDocInfo;
import org.apache.wss4j.api.dom.message.WSSecHeader;
import org.apache.wss4j.api.dom.message.WSSecSignatureBase;
import org.apache.wss4j.api.dom.message.token.KerberosSecurity;
import org.apache.wss4j.api.dom.transform.STRTransform;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;


/**
 * Creates a Signature according to WS Specification, X509 profile.
 *
 * This class is a re-factored implementation of the previous WSS4J class
 * <code>WSSignEnvelope</code>. This new class allows better control of
 * the process to create a Signature and to add it to the Security header.
 *
 * The flexibility and fine granular control is required to implement a handler
 * that uses WSSecurityPolicy files to control the setup of a Security header.
 */
public class WSSecSignature extends WSSecSignatureBase {

    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(WSSecSignature.class);

    private boolean useSingleCert = true;
    private String customTokenValueType;
    private String customTokenId;
    private String encrKeySha1value;
    private Crypto crypto;
    private X509Certificate useThisCert;
    private boolean includeSignatureToken;

    public WSSecSignature(WSSecHeader securityHeader) {
        this(securityHeader, null);
    }

    public WSSecSignature(WSSecHeader securityHeader, Provider provider) {
        super(securityHeader, provider);
    }

    public WSSecSignature(Document doc) {
        this(doc, null);
    }

    public WSSecSignature(Document doc, Provider provider) {
        super(doc, provider);
    }

    /**
     * Initialize a WSSec Signature.
     *
     * The method sets up and initializes a WSSec Signature structure after the
     * relevant information was set. After setup of the references to elements
     * to sign may be added. After all references are added they can be signed.
     *
     * This method does not add the Signature element to the security header.
     * See <code>prependSignatureElementToHeader()</code> method.
     *
     * @param cr An instance of the Crypto API to handle keystore and certificates
     * @throws WSSecurityException
     */
    public void prepare(Crypto cr)
        throws WSSecurityException {
        //
        // Gather some info about the document to process and store it for
        // retrieval
        //
        crypto = cr;
        WSDocInfo wsDocInfo = getWsDocInfo();
        if (wsDocInfo == null) {
            wsDocInfo = new WSDocInfo(getDocument());
            super.setWsDocInfo(wsDocInfo);
        }
        wsDocInfo.setCrypto(cr);

        //
        // At first get the security token (certificate) according to the parameters.
        //
        X509Certificate[] certs = getSigningCerts();

        try {
            C14NMethodParameterSpec c14nSpec = null;
            if (isAddInclusivePrefixes() && getSigCanonicalization().equals(WSConstants.C14N_EXCL_OMIT_COMMENTS)) {
                Element securityHeaderElement = getSecurityHeader().getSecurityHeaderElement();
                List<String> prefixes =
                    getInclusivePrefixes(securityHeaderElement, false);
                c14nSpec = new ExcC14NParameterSpec(prefixes);
            }

           c14nMethod = signatureFactory.newCanonicalizationMethod(getSigCanonicalization(), c14nSpec);
        } catch (Exception ex) {
            LOG.error("", ex);
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.FAILED_SIGNATURE, ex, "noXMLSig"
            );
        }

        keyInfoUri = getIdAllocator().createSecureId("KI-", keyInfo);
        if (!useCustomSecRef && getCustomKeyInfoElement() == null) {
            secRef = new SecurityTokenReference(getDocument());
            strUri = getIdAllocator().createSecureId("STR-", secRef);
            secRef.addWSSENamespace();
            secRef.addWSUNamespace();
            secRef.setID(strUri);

            //
            // Get an initialized XMLSignature element.
            //

            //
            // Prepare and setup the token references for this Signature
            //
            switch (keyIdentifierType) {
            case WSConstants.BST_DIRECT_REFERENCE:
                Reference ref = new Reference(getDocument());
                ref.setURI("#" + certUri);

                addBST(certs);
                if (!useSingleCert) {
                    secRef.addTokenType(PKIPathSecurity.PKI_TYPE);
                    ref.setValueType(PKIPathSecurity.PKI_TYPE);
                } else {
                    ref.setValueType(X509Security.X509_V3_TYPE);
                }
                secRef.setReference(ref);
                break;

                case WSConstants.ISSUER_SERIAL:
                    addIssuerSerial(certs,false);
                    break;

                case WSConstants.ISSUER_SERIAL_QUOTE_FORMAT:
                    addIssuerSerial(certs,true);
                    break;

                case WSConstants.X509_KEY_IDENTIFIER:
                secRef.setKeyIdentifier(certs[0]);
                break;

            case WSConstants.SKI_KEY_IDENTIFIER:
                secRef.setKeyIdentifierSKI(certs[0], crypto);

                if (includeSignatureToken) {
                    addBST(certs);
                }
                break;

            case WSConstants.THUMBPRINT_IDENTIFIER:
                secRef.setKeyIdentifierThumb(certs[0]);

                if (includeSignatureToken) {
                    addBST(certs);
                }
                break;

            case WSConstants.ENCRYPTED_KEY_SHA1_IDENTIFIER:
                if (encrKeySha1value != null) {
                    secRef.setKeyIdentifierEncKeySHA1(encrKeySha1value);
                } else {
                    byte[] digestBytes = KeyUtils.generateDigest(secretKey);
                    secRef.setKeyIdentifierEncKeySHA1(org.apache.xml.security.utils.XMLUtils.encodeToString(digestBytes));
                }
                secRef.addTokenType(WSConstants.WSS_ENC_KEY_VALUE_TYPE);
                break;

            case WSConstants.CUSTOM_SYMM_SIGNING :
                Reference refCust = new Reference(getDocument());
                if (WSConstants.WSS_SAML_KI_VALUE_TYPE.equals(customTokenValueType)) {
                    secRef.addTokenType(WSConstants.WSS_SAML_TOKEN_TYPE);
                    refCust.setValueType(customTokenValueType);
                } else if (WSConstants.WSS_SAML2_KI_VALUE_TYPE.equals(customTokenValueType)) {
                    secRef.addTokenType(WSConstants.WSS_SAML2_TOKEN_TYPE);
                } else if (WSConstants.WSS_ENC_KEY_VALUE_TYPE.equals(customTokenValueType)) {
                    secRef.addTokenType(WSConstants.WSS_ENC_KEY_VALUE_TYPE);
                    refCust.setValueType(customTokenValueType);
                } else if (KerberosSecurity.isKerberosToken(customTokenValueType)) {
                    secRef.addTokenType(customTokenValueType);
                    refCust.setValueType(customTokenValueType);
                } else {
                    refCust.setValueType(customTokenValueType);
                }
                refCust.setURI("#" + customTokenId);
                secRef.setReference(refCust);
                break;

            case WSConstants.CUSTOM_SYMM_SIGNING_DIRECT :
                Reference refCustd = new Reference(getDocument());
                if (WSConstants.WSS_SAML_KI_VALUE_TYPE.equals(customTokenValueType)) {
                    secRef.addTokenType(WSConstants.WSS_SAML_TOKEN_TYPE);
                    refCustd.setValueType(customTokenValueType);
                } else if (WSConstants.WSS_SAML2_KI_VALUE_TYPE.equals(customTokenValueType)) {
                    secRef.addTokenType(WSConstants.WSS_SAML2_TOKEN_TYPE);
                } else if (WSConstants.WSS_ENC_KEY_VALUE_TYPE.equals(customTokenValueType)) {
                    secRef.addTokenType(WSConstants.WSS_ENC_KEY_VALUE_TYPE);
                    refCustd.setValueType(customTokenValueType);
                } else if (KerberosSecurity.isKerberosToken(customTokenValueType)) {
                    secRef.addTokenType(customTokenValueType);
                    refCustd.setValueType(customTokenValueType);
                } else {
                    refCustd.setValueType(customTokenValueType);
                }
                refCustd.setURI(customTokenId);
                secRef.setReference(refCustd);
                break;

            case WSConstants.CUSTOM_KEY_IDENTIFIER:
                if (WSConstants.WSS_SAML_KI_VALUE_TYPE.equals(customTokenValueType)) {
                    secRef.setKeyIdentifier(customTokenValueType, customTokenId);
                    secRef.addTokenType(WSConstants.WSS_SAML_TOKEN_TYPE);
                } else if (WSConstants.WSS_SAML2_KI_VALUE_TYPE.equals(customTokenValueType)) {
                    secRef.setKeyIdentifier(customTokenValueType, customTokenId);
                    secRef.addTokenType(WSConstants.WSS_SAML2_TOKEN_TYPE);
                } else if (WSConstants.WSS_ENC_KEY_VALUE_TYPE.equals(customTokenValueType)) {
                    secRef.setKeyIdentifier(customTokenValueType, customTokenId, true);
                    secRef.addTokenType(WSConstants.WSS_ENC_KEY_VALUE_TYPE);
                } else if (SecurityTokenReference.ENC_KEY_SHA1_URI.equals(customTokenValueType)) {
                    secRef.setKeyIdentifier(customTokenValueType, customTokenId, true);
                    secRef.addTokenType(WSConstants.WSS_ENC_KEY_VALUE_TYPE);
                } else if (WSConstants.WSS_KRB_KI_VALUE_TYPE.equals(customTokenValueType)) {
                    secRef.setKeyIdentifier(customTokenValueType, customTokenId, true);
                    secRef.addTokenType(WSConstants.WSS_GSS_KRB_V5_AP_REQ);
                }
                break;

            case WSConstants.KEY_VALUE:
                java.security.PublicKey publicKey = certs[0].getPublicKey();

                try {
                    KeyInfoFactory keyInfoFactory = signatureFactory.getKeyInfoFactory();
                    KeyValue keyValue = keyInfoFactory.newKeyValue(publicKey);
                    keyInfo =
                        keyInfoFactory.newKeyInfo(Collections.singletonList(keyValue), keyInfoUri);
                } catch (java.security.KeyException ex) {
                    LOG.error("", ex);
                    throw new WSSecurityException(
                        WSSecurityException.ErrorCode.FAILED_SIGNATURE, ex, "noXMLSig"
                    );
                }
                break;
            default:
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "unsupportedKeyId");
            }
        }

        if (keyIdentifierType != WSConstants.KEY_VALUE) {
            marshalKeyInfo(wsDocInfo);
        }
    }

    private void addIssuerSerial(X509Certificate[] certs,boolean isCommaDelimited) throws WSSecurityException {
        String issuer = certs[0].getIssuerX500Principal().getName();
        java.math.BigInteger serialNumber = certs[0].getSerialNumber();

        DOMX509IssuerSerial domIssuerSerial
                = new DOMX509IssuerSerial(getDocument(), issuer, serialNumber, isCommaDelimited);
        DOMX509Data domX509Data = new DOMX509Data(getDocument(), domIssuerSerial);
        secRef.setUnknownElement(domX509Data.getElement());

        if (includeSignatureToken) {
            addBST(certs);
        }
    }

    /**
     * Builds a signed soap envelope.
     *
     * This is a convenience method and for backward compatibility. The method
     * creates a Signature and puts it into the Security header. It does so by
     * calling the single functions in order to perform a <i>one shot signature</i>.
     *
     * @param cr An instance of the Crypto API to handle keystore and certificates
     * @return A signed SOAP envelope as <code>Document</code>
     * @throws WSSecurityException
     */
    public Document build(Crypto cr)
        throws WSSecurityException {

        LOG.debug("Beginning signing...");

        prepare(cr);
        if (getParts().isEmpty()) {
            String soapNamespace = XMLUtils.getSOAPNamespace(getDocument().getDocumentElement());
            WSEncryptionPart defaultEncryptionPart = 
                new WSEncryptionPart(WSConstants.ELEM_BODY, soapNamespace, "Content");
            getParts().add(defaultEncryptionPart);
        } else {
            for (WSEncryptionPart part : getParts()) {
                if (part.getId() == null && "STRTransform".equals(part.getName())) {
                    part.setId(strUri);
                } else if ("KeyInfo".equals(part.getName()) && WSConstants.SIG_NS.equals(part.getNamespace())
                    && part.getElement() == null) {
                    // Special code to sign the KeyInfo
                    part.setId(keyInfoUri);
                }
            }
        }

        List<javax.xml.crypto.dsig.Reference> referenceList = addReferencesToSign(getParts());

        computeSignature(referenceList);

        //
        // if we have a BST prepend it in front of the Signature according to
        // strict layout rules.
        //
        if (bstToken != null) {
            prependBSTElementToHeader();
        }

        return getDocument();
    }

    /**
     * Returns the SignatureElement.
     * The method can be called any time after <code>prepare()</code>.
     * @return The DOM Element of the signature.
     */
    public Element getSignatureElement() {
        Element securityHeaderElement = getSecurityHeader().getSecurityHeaderElement();
        return
            XMLUtils.getDirectChildElement(
                securityHeaderElement, WSConstants.SIG_LN, WSConstants.SIG_NS
            );
    }

    /**
     * Add a BinarySecurityToken
     */
    private void addBST(X509Certificate[] certs) throws WSSecurityException {
        if (storeBytesInAttachment) {
            bstToken =
                getDocument().createElementNS(WSS4JConstants.WSSE_NS, "wsse:BinarySecurityToken");
            bstToken.setAttributeNS(null, "EncodingType", WSS4JConstants.BASE64_ENCODING);
            bstToken.setAttributeNS(WSS4JConstants.WSU_NS, WSS4JConstants.WSU_PREFIX + ":Id", certUri);
            if (addWSUNamespace) {
                bstToken.setAttributeNS(XMLUtils.XMLNS_NS, "xmlns:" + WSConstants.WSU_PREFIX, WSConstants.WSU_NS);
            }

            byte[] certBytes = null;
            if (!useSingleCert) {
                bstToken.setAttributeNS(null, "ValueType", PKIPathSecurity.PKI_TYPE);
                certBytes = crypto.getBytesFromCertificates(certs);
            } else {
                bstToken.setAttributeNS(null, "ValueType", X509Security.X509_V3_TYPE);
                try {
                    certBytes = certs[0].getEncoded();
                } catch (CertificateEncodingException e) {
                    throw new WSSecurityException(
                        WSSecurityException.ErrorCode.SECURITY_TOKEN_UNAVAILABLE, e, "encodeError"
                    );
                }
            }

            final String attachmentId = getIdAllocator().createId("", getDocument());
            AttachmentUtils.storeBytesInAttachment(bstToken, getDocument(), attachmentId,
                                                  certBytes, attachmentCallbackHandler);
            getWsDocInfo().addTokenElement(bstToken, false);
        } else {
            BinarySecurity binarySecurity = null;
            if (!useSingleCert) {
                binarySecurity = new PKIPathSecurity(getDocument());
                ((PKIPathSecurity) binarySecurity).setX509Certificates(certs, crypto);
            } else {
                binarySecurity = new X509Security(getDocument());
                ((X509Security) binarySecurity).setX509Certificate(certs[0]);
            }
            binarySecurity.setID(certUri);
            if (addWSUNamespace) {
                binarySecurity.addWSUNamespace();
            }
            bstToken = binarySecurity.getElement();
            getWsDocInfo().addTokenElement(bstToken, false);
        }

        bstAddedToSecurityHeader = false;
    }

    /**
     * Compute the Signature over the references. The signature element will be
     * prepended to the security header.
     *
     * This method can be called any time after the references were set. See
     * <code>addReferencesToSign()</code>.
     *
     * @param referenceList The list of references to sign
     *
     * @throws WSSecurityException
     */
    public void computeSignature(
        List<javax.xml.crypto.dsig.Reference> referenceList
    ) throws WSSecurityException {
        computeSignature(referenceList, true, null);
    }

    /**
     * Compute the Signature over the references.
     *
     * This method can be called any time after the references were set. See
     * <code>addReferencesToSign()</code>.
     *
     * @param referenceList The list of references to sign
     * @param prepend Whether to prepend the signature element to the security header
     * @param siblingElement If prepending, then prepend before this sibling Element
     *
     * @throws WSSecurityException
     */
    public void computeSignature(
        List<javax.xml.crypto.dsig.Reference> referenceList,
        boolean prepend,
        Element siblingElement
    ) throws WSSecurityException {
        try {
            java.security.Key key;
            if (secretKey == null) {
                key = crypto.getPrivateKey(user, password);
            } else {
                key = KeyUtils.prepareSecretKey(getSignatureAlgorithm(), secretKey);
            }
            SignatureMethod signatureMethod =
                signatureFactory.newSignatureMethod(getSignatureAlgorithm(), null);
            SignedInfo signedInfo =
                signatureFactory.newSignedInfo(c14nMethod, signatureMethod, referenceList);

            sig = signatureFactory.newXMLSignature(
                    signedInfo,
                    keyInfo,
                    null,
                    getIdAllocator().createId("SIG-", null),
                    null);

            //
            // Figure out where to insert the signature element
            //
            XMLSignContext signContext = null;
            Element securityHeaderElement = getSecurityHeader().getSecurityHeaderElement();
            if (prepend) {
                if (siblingElement == null) {
                    Node child = securityHeaderElement.getFirstChild();
                    while (child != null && child.getNodeType() != Node.ELEMENT_NODE) {
                        child = child.getNextSibling();
                    }
                    siblingElement = (Element)child;
                }
                if (siblingElement == null) {
                    signContext = new DOMSignContext(key, securityHeaderElement);
                } else {
                    signContext = new DOMSignContext(key, securityHeaderElement, siblingElement);
                }
            } else {
                signContext = new DOMSignContext(key, securityHeaderElement);
            }
            if (getSignatureProvider() != null) {
                signContext.setProperty("org.jcp.xml.dsig.internal.dom.SignatureProvider", getSignatureProvider());
            }

            signContext.putNamespacePrefix(WSConstants.SIG_NS, WSConstants.SIG_PREFIX);
            if (WSConstants.C14N_EXCL_OMIT_COMMENTS.equals(getSigCanonicalization())) {
                signContext.putNamespacePrefix(
                    WSConstants.C14N_EXCL_OMIT_COMMENTS,
                    WSConstants.C14N_EXCL_OMIT_COMMENTS_PREFIX
                );
            }
            signContext.setProperty(STRTransform.TRANSFORM_WS_DOC_INFO, getWsDocInfo());
            getWsDocInfo().setCallbackLookup(callbackLookup);

            // Add the elements to sign to the Signature Context
            getWsDocInfo().setTokensOnContext((DOMSignContext)signContext);
            sig.sign(signContext);

            signatureValue = sig.getSignatureValue().getValue();

            cleanup();
        } catch (Exception ex) {
            LOG.error(ex.getMessage(), ex);
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.FAILED_SIGNATURE, ex
            );
        }
    }

    /**
     * Set the single cert flag.
     *
     * @param useSingleCert
     */
    public void setUseSingleCertificate(boolean useSingleCert) {
        this.useSingleCert = useSingleCert;
    }

    /**
     * Get the single cert flag.
     *
     * @return A boolean if single certificate is set.
     */
    public boolean isUseSingleCertificate() {
        return useSingleCert;
    }

    /**
     * Get the id generated during <code>prepare()</code>.
     *
     * Returns the the value of wsu:Id attribute of the Signature element.
     *
     * @return Return the wsu:Id of this token or null if <code>prepare()</code>
     *         was not called before.
     */
    public String getId() {
        if (sig == null) {
            return null;
        }
        return sig.getId();
    }

    /**
     * Get the id of the BST generated during <code>prepare()</code>.
     *
     * @return Returns the the value of wsu:Id attribute of the
     * BinaruSecurityToken element.
     */
    public String getBSTTokenId() {
        if (bstToken == null) {
            return null;
        }
        return bstToken.getAttributeNS(WSS4JConstants.WSU_NS, "Id");
    }

    /**
     * Set the custom token value type to use
     * @param customTokenValueType the custom token value type to use
     */
    public void setCustomTokenValueType(String customTokenValueType) {
        this.customTokenValueType = customTokenValueType;
    }

    /**
     * Set the custom token id
     * @param customTokenId the custom token id
     */
    public void setCustomTokenId(String customTokenId) {
        this.customTokenId = customTokenId;
    }

    public String getCustomTokenId() {
        return this.customTokenId;
    }

    /**
     * Set the encrypted key sha1 value
     * @param encrKeySha1value the encrypted key sha1 value
     */
    public void setEncrKeySha1value(String encrKeySha1value) {
        this.encrKeySha1value = encrKeySha1value;
    }

    /**
     * Set the X509 Certificate to use
     * @param cer the X509 Certificate to use
     */
    public void setX509Certificate(X509Certificate cer) {
        this.useThisCert = cer;
    }

    /**
     * Returns the BST Token element.
     * The method can be called any time after <code>prepare()</code>.
     * @return the BST Token element
     */
    public Element getBinarySecurityTokenElement() {
        return bstToken;
    }

    /**
     * @return the URI associated with the SecurityTokenReference
     * (must be called after {@link #prepare(Document, Crypto)}
     */
    public String getSecurityTokenReferenceURI() {
        return strUri;
    }

    /**
     * Set up the X509 Certificate(s) for signing.
     */
    private X509Certificate[] getSigningCerts() throws WSSecurityException {
        X509Certificate[] certs = null;
        if (!(keyIdentifierType == WSConstants.CUSTOM_SYMM_SIGNING
            || keyIdentifierType == WSConstants.CUSTOM_SYMM_SIGNING_DIRECT
            || keyIdentifierType == WSConstants.ENCRYPTED_KEY_SHA1_IDENTIFIER
            || keyIdentifierType == WSConstants.CUSTOM_KEY_IDENTIFIER)) {
            if (useThisCert == null) {
                CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
                cryptoType.setAlias(user);
                if (crypto == null) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "noSigCryptoFile");
                }
                certs = crypto.getX509Certificates(cryptoType);
            } else {
                certs = new X509Certificate[] {useThisCert};
            }
            if (certs == null || certs.length <= 0) {
                throw new WSSecurityException(
                        WSSecurityException.ErrorCode.FAILURE,
                        "noUserCertsFound",
                        new Object[] {user, "signature"});
            }
            certUri = getIdAllocator().createSecureId("X509-", certs[0]);
            //
            // If no signature algorithm was set try to detect it according to the
            // data stored in the certificate.
            //
            if (getSignatureAlgorithm() == null) {
                String pubKeyAlgo = certs[0].getPublicKey().getAlgorithm();
                LOG.debug("Automatic signature algorithm detection: {}", pubKeyAlgo);
                if (pubKeyAlgo.equalsIgnoreCase("DSA")) {
                    setSignatureAlgorithm(WSConstants.DSA);
                } else if (pubKeyAlgo.equalsIgnoreCase("RSA")) {
                    setSignatureAlgorithm(WSConstants.RSA);
                } else if (pubKeyAlgo.equalsIgnoreCase("EC")) {
                    setSignatureAlgorithm(WSConstants.ECDSA_SHA256);
                } else if (pubKeyAlgo.equalsIgnoreCase("Ed25519")) {
                    setSignatureAlgorithm(WSConstants.ED25519);
                } else if (pubKeyAlgo.equalsIgnoreCase("ED448")) {
                    setSignatureAlgorithm(WSConstants.ED448);
                } else if (pubKeyAlgo.equalsIgnoreCase("EdDSA")) {
                    setSignatureAlgorithm(getSigAlgorithmForEdDSAKey(certs[0].getPublicKey()));
                } else {
                    throw new WSSecurityException(
                        WSSecurityException.ErrorCode.FAILURE,
                        "unknownSignatureAlgorithm",
                        new Object[] {pubKeyAlgo});
                }
            }
        }
        return certs;
    }

    /**
     * The method returns EdDSA signature algorithm URI for public key type (Ed25519 or Ed448).
     *
     * @param publicKey the public key to get the algorithm from
     * @return the signature algorithm URI (ED25519 or ED448) for the EdDSA public key
     * @throws WSSecurityException if the algorithm cannot be determined
     */
    private static String getSigAlgorithmForEdDSAKey(PublicKey publicKey) throws WSSecurityException {

        if (!"x.509".equalsIgnoreCase(publicKey.getFormat())) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "unknownAlgorithm",
                    new Object[]{"Unknown cert format!"});
        }

        DERDecoder decoder = new DERDecoder(publicKey.getEncoded());
        // find TYPE_OBJECT_IDENTIFIER (OID) for the public key algorithm
        decoder.expect(decoder.TYPE_SEQUENCE);
        decoder.getLength();
        decoder.expect(decoder.TYPE_SEQUENCE);
        decoder.getLength();
        decoder.expect(decoder.TYPE_OBJECT_IDENTIFIER);
        int size = decoder.getLength();
        if (size != 3) {
            LOG.debug("Invalid ECDSA Public key OID byte size: [{}]", size);
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, "invalidCert");
        }

        //  The first two nodes 1.3 of the OID are encoded onto a single byte. The first node is multiplied by 40
        //  and the result is added to the value of the second node 3 which gives 43 or 0x2B.
        decoder.expect(43);
        // The second byte is expected 101 from the OID 1.3.101 (EdDSA)
        decoder.expect(101);
        // The third byte defines algorithm 112 is for Ed25519 and 113 is for Ed448
        byte algDef = decoder.getBytes(1)[0];
        switch (algDef) {
            case 112:
                return WSConstants.ED25519;
            case 113:
                return WSConstants.ED448;
            default:
                throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, "unknownAlgorithm",
                        new Object[]{"Invalid ECDSA Public key OID!"});
        }
    }

    public boolean isIncludeSignatureToken() {
        return includeSignatureToken;
    }

    public void setIncludeSignatureToken(boolean includeSignatureToken) {
        this.includeSignatureToken = includeSignatureToken;
    }

    public String getKeyInfoUri() {
        return keyInfoUri;
    }
}
