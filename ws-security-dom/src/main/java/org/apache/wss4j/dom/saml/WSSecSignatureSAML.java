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

package org.apache.wss4j.dom.saml;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.XMLSignContext;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.ExcC14NParameterSpec;

import org.apache.wss4j.common.SignatureActionToken;
import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.OpenSAMLUtil;
import org.apache.wss4j.common.saml.SAMLKeyInfo;
import org.apache.wss4j.common.saml.SAMLUtil;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.token.BinarySecurity;
import org.apache.wss4j.common.token.DOMX509Data;
import org.apache.wss4j.common.token.DOMX509IssuerSerial;
import org.apache.wss4j.common.token.Reference;
import org.apache.wss4j.common.token.SecurityTokenReference;
import org.apache.wss4j.common.token.X509Security;
import org.apache.wss4j.common.util.KeyUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSDocInfo;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecSignature;
import org.apache.wss4j.dom.transform.STRTransform;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class WSSecSignatureSAML extends WSSecSignature {

    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(WSSecSignatureSAML.class);
    private boolean senderVouches;
    private SecurityTokenReference secRefSaml;
    private String secRefID;
    private Element samlToken;
    private Crypto userCrypto;
    private Crypto issuerCrypto;
    private String issuerKeyName;
    private String issuerKeyPW;
    private boolean useDirectReferenceToAssertion;

    /**
     * Constructor.
     */
    public WSSecSignatureSAML(WSSecHeader securityHeader) {
        super(securityHeader);
        doDebug = LOG.isDebugEnabled();
    }
    
    public WSSecSignatureSAML(Document doc) {
        super(doc);
        doDebug = LOG.isDebugEnabled();
    }

    /**
     * Builds a signed soap envelope with SAML token.
     *
     * The method first gets an appropriate security header. According to the
     * defined parameters for certificate handling the signature elements are
     * constructed and inserted into the <code>wsse:Signature</code>
     *
     * @param uCrypto
     *            The user's Crypto instance
     * @param samlAssertion
     *            the complete SAML assertion
     * @param iCrypto
     *            An instance of the Crypto API to handle keystore SAML token
     *            issuer and to generate certificates
     * @param iKeyName
     *            Private key to use in case of "sender-Vouches"
     * @param iKeyPW
     *            Password for issuer private key
     * @return A signed SOAP envelope as <code>Document</code>
     * @throws WSSecurityException
     */
    public Document build(
        Crypto uCrypto, SamlAssertionWrapper samlAssertion,
        Crypto iCrypto, String iKeyName, String iKeyPW
    ) throws WSSecurityException {

        prepare(uCrypto, samlAssertion, iCrypto, iKeyName, iKeyPW);

        if (getParts().isEmpty()) {
            getParts().add(WSSecurityUtil.getDefaultEncryptionPart(getDocument()));
        } else {
            for (WSEncryptionPart part : getParts()) {
                if ("STRTransform".equals(part.getName()) && part.getId() == null) {
                    part.setId(strUri);
                }
            }
        }

        //
        // Add the STRTransform for the SecurityTokenReference to the SAML assertion
        // if it exists
        //
        if (secRefID != null) {
            String soapNamespace =
                WSSecurityUtil.getSOAPNamespace(getDocument().getDocumentElement());
            WSEncryptionPart encP =
                new WSEncryptionPart("STRTransform", soapNamespace, "Content");
            encP.setId(secRefID);
            getParts().add(encP);
        }

        List<javax.xml.crypto.dsig.Reference> referenceList = addReferencesToSign(getParts());

        prependSAMLElementsToHeader();

        if (senderVouches) {
            computeSignature(referenceList, secRefSaml.getElement());
        } else {
            computeSignature(referenceList, samlToken);
        }

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
     * Initialize a WSSec SAML Signature.
     *
     * The method sets up and initializes a WSSec SAML Signature structure after
     * the relevant information was set. After setup of the references to
     * elements to sign may be added. After all references are added they can be
     * signed.
     *
     * This method does not add the Signature element to the security header.
     * See <code>prependSignatureElementToHeader()</code> method.
     *
     * @param uCrypto
     *            The user's Crypto instance
     * @param samlAssertion
     *            the complete SAML assertion
     * @param iCrypto
     *            An instance of the Crypto API to handle keystore SAML token
     *            issuer and to generate certificates
     * @param iKeyName
     *            Private key to use in case of "sender-Vouches"
     * @param iKeyPW
     *            Password for issuer private key
     * @throws WSSecurityException
     */
    public void prepare(
        Crypto uCrypto, SamlAssertionWrapper samlAssertion, Crypto iCrypto,
        String iKeyName, String iKeyPW
    ) throws WSSecurityException {

        if (doDebug) {
            LOG.debug("Beginning ST signing...");
        }

        userCrypto = uCrypto;
        issuerCrypto = iCrypto;
        issuerKeyName = iKeyName;
        issuerKeyPW = iKeyPW;

        samlToken = samlAssertion.toDOM(getDocument());

        //
        // Get some information about the SAML token content. This controls how
        // to deal with the whole stuff. First get the Authentication statement
        // (includes Subject), then get the _first_ confirmation method only
        // thats if "senderVouches" is true.
        //
        String confirmMethod = null;
        List<String> methods = samlAssertion.getConfirmationMethods();
        if (methods != null && methods.size() > 0) {
            confirmMethod = methods.get(0);
        }
        if (OpenSAMLUtil.isMethodSenderVouches(confirmMethod)) {
            senderVouches = true;
        }
        //
        // Gather some info about the document to process and store it for
        // retrieval
        //
        if (super.getWsDocInfo() == null) {
            WSDocInfo wsDocInfo = new WSDocInfo(getDocument());
            super.setWsDocInfo(wsDocInfo);
        }


        X509Certificate[] certs = null;
        PublicKey publicKey = null;

        if (senderVouches) {
            CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
            cryptoType.setAlias(issuerKeyName);
            certs = issuerCrypto.getX509Certificates(cryptoType);
            getWsDocInfo().setCrypto(issuerCrypto);
        } else {
            //
            // in case of key holder: - get the user's certificate that _must_ be
            // included in the SAML token. To ensure the cert integrity the SAML
            // token must be signed (by the issuer).
            //
            if (userCrypto == null || !samlAssertion.isSigned()) {
                throw new WSSecurityException(
                    WSSecurityException.ErrorCode.FAILURE,
                    "invalidSAMLsecurity",
                    new Object[] {"for SAML Signature (Key Holder)"});
            }
            if (secretKey == null) {
                RequestData data = new RequestData();
                SignatureActionToken actionToken = new SignatureActionToken();
                data.setSignatureToken(actionToken);
                actionToken.setCrypto(userCrypto);
                SAMLKeyInfo samlKeyInfo =
                    SAMLUtil.getCredentialFromSubject(
                            samlAssertion, new WSSSAMLKeyInfoProcessor(data, getWsDocInfo()),
                            userCrypto, data.getCallbackHandler()
                    );
                if (samlKeyInfo != null) {
                    publicKey = samlKeyInfo.getPublicKey();
                    certs = samlKeyInfo.getCerts();
                    getWsDocInfo().setCrypto(userCrypto);
                }
            }
        }
        if ((certs == null || certs.length == 0 || certs[0] == null)
            && publicKey == null && secretKey == null) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.FAILURE,
                "noCertsFound",
                new Object[] {"SAML signature"});
        }

        if (getSignatureAlgorithm() == null) {
            PublicKey key = null;
            if (certs != null && certs[0] != null) {
                key = certs[0].getPublicKey();
            } else if (publicKey != null) {
                key = publicKey;
            } else {
                throw new WSSecurityException(
                    WSSecurityException.ErrorCode.FAILURE, "unknownSignatureAlgorithm"
                );
            }

            String pubKeyAlgo = key.getAlgorithm();
            if (doDebug) {
                LOG.debug("automatic sig algo detection: " + pubKeyAlgo);
            }
            if (pubKeyAlgo.equalsIgnoreCase("DSA")) {
                setSignatureAlgorithm(WSConstants.DSA);
            } else if (pubKeyAlgo.equalsIgnoreCase("RSA")) {
                setSignatureAlgorithm(WSConstants.RSA);
            } else {
                throw new WSSecurityException(
                    WSSecurityException.ErrorCode.FAILURE,
                    "unknownSignatureAlgorithm",
                    new Object[] {pubKeyAlgo});
            }
        }
        sig = null;

        try {
            C14NMethodParameterSpec c14nSpec = null;
            if (isAddInclusivePrefixes() && getSigCanonicalization().equals(WSConstants.C14N_EXCL_OMIT_COMMENTS)) {
                Element securityHeaderElement = getSecurityHeader().getSecurityHeaderElement();
                List<String> prefixes = getInclusivePrefixes(securityHeaderElement, false);
                c14nSpec = new ExcC14NParameterSpec(prefixes);
            }

           c14nMethod =
               signatureFactory.newCanonicalizationMethod(getSigCanonicalization(), c14nSpec);
        } catch (Exception ex) {
            LOG.error("", ex);
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.FAILED_SIGNATURE, ex, "noXMLSig"
            );
        }

        keyInfoUri = getIdAllocator().createSecureId("KeyId-", keyInfo);
        SecurityTokenReference secRef = new SecurityTokenReference(getDocument());
        strUri = getIdAllocator().createSecureId("STRId-", secRef);
        secRef.setID(strUri);
        setSecurityTokenReference(secRef);

        if (certs != null && certs.length != 0) {
            certUri = getIdAllocator().createSecureId("CertId-", certs[0]);
        }

        //
        // If the sender vouches, then we must sign the SAML token _and_ at
        // least one part of the message (usually the SOAP body). To do so we
        // need to - put in a reference to the SAML token. Thus we create a STR
        // and insert it into the wsse:Security header - set a reference of the
        // created STR to the signature and use STR Transform during the
        // signature
        //
        try {
            if (senderVouches) {
                secRefSaml = new SecurityTokenReference(getDocument());
                secRefID = getIdAllocator().createSecureId("STRSAMLId-", secRefSaml);
                secRefSaml.setID(secRefID);

                if (useDirectReferenceToAssertion) {
                    Reference ref = new Reference(getDocument());
                    ref.setURI("#" + samlAssertion.getId());
                    if (samlAssertion.getSaml1() != null) {
                        ref.setValueType(WSConstants.WSS_SAML_KI_VALUE_TYPE);
                        secRefSaml.addTokenType(WSConstants.WSS_SAML_TOKEN_TYPE);
                    } else if (samlAssertion.getSaml2() != null) {
                        secRefSaml.addTokenType(WSConstants.WSS_SAML2_TOKEN_TYPE);
                    }
                    secRefSaml.setReference(ref);
                } else {
                    Element keyId = getDocument().createElementNS(WSConstants.WSSE_NS, "wsse:KeyIdentifier");
                    String valueType = null;
                    if (samlAssertion.getSaml1() != null) {
                        valueType = WSConstants.WSS_SAML_KI_VALUE_TYPE;
                        secRefSaml.addTokenType(WSConstants.WSS_SAML_TOKEN_TYPE);
                    } else if (samlAssertion.getSaml2() != null) {
                        valueType = WSConstants.WSS_SAML2_KI_VALUE_TYPE;
                        secRefSaml.addTokenType(WSConstants.WSS_SAML2_TOKEN_TYPE);
                    }
                    keyId.setAttributeNS(
                        null, "ValueType", valueType
                    );
                    keyId.appendChild(getDocument().createTextNode(samlAssertion.getId()));
                    Element elem = secRefSaml.getElement();
                    elem.appendChild(keyId);
                }
                getWsDocInfo().addTokenElement(secRefSaml.getElement(), false);
            }
        } catch (Exception ex) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.FAILED_SIGNATURE, ex, "noXMLSig"
            );
        }

        X509Certificate cert = certs != null ? certs[0] : null;
        configureKeyInfo(secRef, cert, iCrypto != null ? iCrypto : uCrypto, samlAssertion);

        getWsDocInfo().addTokenElement(samlToken, false);
    }
    
    private void configureKeyInfo(
        SecurityTokenReference secRef, X509Certificate cert,
        Crypto crypto, SamlAssertionWrapper samlAssertion
    ) throws WSSecurityException {
        if (senderVouches) {
            switch (keyIdentifierType) {
            case WSConstants.BST_DIRECT_REFERENCE:
                Reference ref = new Reference(getDocument());
                ref.setURI("#" + certUri);
                BinarySecurity binarySecurity = new X509Security(getDocument());
                ((X509Security) binarySecurity).setX509Certificate(cert);
                binarySecurity.setID(certUri);
                bstToken = binarySecurity.getElement();
                getWsDocInfo().addTokenElement(bstToken, false);
                ref.setValueType(binarySecurity.getValueType());
                secRef.setReference(ref);
                break;

            case WSConstants.X509_KEY_IDENTIFIER :
                secRef.setKeyIdentifier(cert);
                break;

            case WSConstants.SKI_KEY_IDENTIFIER:
                secRef.setKeyIdentifierSKI(cert, crypto);
                break;

            case WSConstants.THUMBPRINT_IDENTIFIER:
                secRef.setKeyIdentifierThumb(cert);
                break;

            case WSConstants.ISSUER_SERIAL:
                final String issuer = cert.getIssuerDN().getName();
                final java.math.BigInteger serialNumber = cert.getSerialNumber();
                final DOMX509IssuerSerial domIssuerSerial =
                        new DOMX509IssuerSerial(getDocument(), issuer, serialNumber);
                final DOMX509Data domX509Data = new DOMX509Data(getDocument(), domIssuerSerial);
                secRef.setUnknownElement(domX509Data.getElement());
                break;

            default:
                throw new WSSecurityException(
                    WSSecurityException.ErrorCode.FAILURE, "unsupportedKeyId"
                );
            }
        } else if (useDirectReferenceToAssertion) {
            Reference ref = new Reference(getDocument());
            ref.setURI("#" + samlAssertion.getId());
            if (samlAssertion.getSaml1() != null) {
                ref.setValueType(WSConstants.WSS_SAML_KI_VALUE_TYPE);
                secRef.addTokenType(WSConstants.WSS_SAML_TOKEN_TYPE);
            } else if (samlAssertion.getSaml2() != null) {
                secRef.addTokenType(WSConstants.WSS_SAML2_TOKEN_TYPE);
            }
            secRef.setReference(ref);
        } else {
            Element keyId = getDocument().createElementNS(WSConstants.WSSE_NS, "wsse:KeyIdentifier");
            String valueType = null;
            if (samlAssertion.getSaml1() != null) {
                valueType = WSConstants.WSS_SAML_KI_VALUE_TYPE;
                secRef.addTokenType(WSConstants.WSS_SAML_TOKEN_TYPE);
            } else if (samlAssertion.getSaml2() != null) {
                valueType = WSConstants.WSS_SAML2_KI_VALUE_TYPE;
                secRef.addTokenType(WSConstants.WSS_SAML2_TOKEN_TYPE);
            }
            keyId.setAttributeNS(
                null, "ValueType", valueType
            );
            keyId.appendChild(getDocument().createTextNode(samlAssertion.getId()));
            Element elem = secRef.getElement();
            elem.appendChild(keyId);
        }
        XMLStructure structure = new DOMStructure(secRef.getElement());
        getWsDocInfo().addTokenElement(secRef.getElement(), false);

        KeyInfoFactory keyInfoFactory = signatureFactory.getKeyInfoFactory();
        keyInfo =
            keyInfoFactory.newKeyInfo(
                java.util.Collections.singletonList(structure), keyInfoUri
            );
    }

    /**
     * Prepend the SAML elements to the elements already in the Security header.
     *
     * The method can be called any time after <code>prepare()</code>. This
     * allows to insert the SAML elements at any position in the Security
     * header.
     *
     * This methods first prepends the SAML security reference if mode is
     * <code>senderVouches</code>, then the SAML token itself,
     */
    public void prependSAMLElementsToHeader() {
        Element securityHeaderElement = getSecurityHeader().getSecurityHeaderElement();
        if (senderVouches) {
            WSSecurityUtil.prependChildElement(securityHeaderElement, secRefSaml.getElement());
        }

        WSSecurityUtil.prependChildElement(securityHeaderElement, samlToken);
    }


    /**
     * Compute the Signature over the references.
     *
     * After references are set this method computes the Signature for them.
     * This method can be called any time after the references were set. See
     * <code>addReferencesToSign()</code>.
     *
     * @throws WSSecurityException
     */
    public void computeSignature(
        List<javax.xml.crypto.dsig.Reference> referenceList,
        Element siblingElement
    ) throws WSSecurityException {
        try {
            java.security.Key key;
            if (senderVouches) {
                key = issuerCrypto.getPrivateKey(issuerKeyName, issuerKeyPW);
            } else if (secretKey != null) {
                key = KeyUtils.prepareSecretKey(getSignatureAlgorithm(), secretKey);
            } else {
                key = userCrypto.getPrivateKey(user, password);
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

            Element securityHeaderElement = getSecurityHeader().getSecurityHeaderElement();
            //
            // Prepend the signature element to the security header (after the assertion)
            //
            XMLSignContext signContext = null;
            if (siblingElement != null && siblingElement.getNextSibling() != null) {
                signContext =
                    new DOMSignContext(key, securityHeaderElement, siblingElement.getNextSibling());
            } else {
                signContext = new DOMSignContext(key, securityHeaderElement);
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
        } catch (Exception ex) {
            LOG.error(ex.getMessage(), ex);
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.FAILED_SIGNATURE, ex
            );
        }
    }

    /**
     * Return whether a Direct Reference is to be used to reference the assertion. The
     * default is false.
     * @return whether a Direct Reference is to be used to reference the assertion
     */
    public boolean isUseDirectReferenceToAssertion() {
        return useDirectReferenceToAssertion;
    }

    /**
     * Set whether a Direct Reference is to be used to reference the assertion. The
     * default is false.
     * @param useDirectReferenceToAssertion whether a Direct Reference is to be used
     *        to reference the assertion
     */
    public void setUseDirectReferenceToAssertion(boolean useDirectReferenceToAssertion) {
        this.useDirectReferenceToAssertion = useDirectReferenceToAssertion;
    }

}
