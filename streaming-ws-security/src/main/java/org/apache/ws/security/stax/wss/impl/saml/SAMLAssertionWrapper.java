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
package org.apache.ws.security.stax.wss.impl.saml;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.saml1.core.*;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.AuthzDecisionStatement;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.security.x509.X509KeyInfoGeneratorFactory;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.validation.ValidationException;
import org.apache.ws.security.common.crypto.Crypto;
import org.apache.ws.security.common.crypto.CryptoType;
import org.apache.ws.security.common.ext.WSPasswordCallback;
import org.apache.ws.security.common.ext.WSSecurityException;
import org.apache.ws.security.stax.wss.ext.*;
import org.apache.ws.security.stax.wss.impl.saml.builder.SAML1ComponentBuilder;
import org.apache.ws.security.stax.wss.impl.saml.builder.SAML2ComponentBuilder;
import org.apache.xml.security.stax.ext.XMLSecurityException;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.keyinfo.X509IssuerSerial;
import javax.xml.namespace.QName;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SAMLAssertionWrapper {

    protected static final transient Log logger = LogFactory.getLog(SAMLAssertionWrapper.class);

    /**
     * Raw SAML assertion data
     */
    private XMLObject xmlObject = null;
    /**
     * Typed SAML v1.1 assertion
     */
    private org.opensaml.saml1.core.Assertion saml1 = null;

    /**
     * Typed SAML v2.0 assertion
     */
    private org.opensaml.saml2.core.Assertion saml2 = null;

    /**
     * The Assertion as a DOM element
     */
    private Element assertionElement;

    /**
     * Default Canonicalization algorithm used for signing.
     */
    private final String defaultCanonicalizationAlgorithm = SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS;

    /**
     * Default RSA Signature algorithm used for signing.
     */
    private final String defaultRSASignatureAlgorithm = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1;

    /**
     * Default DSA Signature algorithm used for signing.
     */
    private final String defaultDSASignatureAlgorithm = SignatureConstants.ALGO_ID_SIGNATURE_DSA;
    
    /**
     * Whether this object was instantiated with a DOM Element or an XMLObject initially
     */
    private final boolean fromDOM;

    /**
     * Constructor AssertionWrapper creates a new AssertionWrapper instance.
     *
     * @param element of type Element
     * @throws UnmarshallingException when
     */
    public SAMLAssertionWrapper(Element element) throws WSSecurityException {
        OpenSAMLUtil.initSamlEngine();

        parseElement(element);
        fromDOM = true;
    }

    /**
     * Constructor AssertionWrapper creates a new AssertionWrapper instance.
     *
     * @param saml2 of type Assertion
     */
    public SAMLAssertionWrapper(org.opensaml.saml2.core.Assertion saml2) throws XMLSecurityException {
        this((XMLObject) saml2);
    }

    /**
     * Constructor AssertionWrapper creates a new AssertionWrapper instance.
     *
     * @param saml1 of type Assertion
     */
    public SAMLAssertionWrapper(org.opensaml.saml1.core.Assertion saml1) throws XMLSecurityException {
        this((XMLObject) saml1);
    }

    /**
     * Constructor AssertionWrapper creates a new AssertionWrapper instance.
     * This is the primary constructor.  All other constructor calls should
     * be routed to this method to ensure that the wrapper is initialized
     * correctly.
     *
     * @param xmlObject of type XMLObject
     */
    public SAMLAssertionWrapper(XMLObject xmlObject) {
        OpenSAMLUtil.initSamlEngine();

        this.xmlObject = xmlObject;
        if (xmlObject instanceof org.opensaml.saml1.core.Assertion) {
            this.saml1 = (org.opensaml.saml1.core.Assertion) xmlObject;
        } else if (xmlObject instanceof org.opensaml.saml2.core.Assertion) {
            this.saml2 = (org.opensaml.saml2.core.Assertion) xmlObject;
        } else {
            logger.error(
                    "AssertionWrapper: found unexpected type "
                            + (xmlObject != null ? xmlObject.getClass().getName() : xmlObject)
            );
        }
        fromDOM = false;
    }


    public SAMLAssertionWrapper(SAMLCallback samlCallback) throws XMLSecurityException {
        OpenSAMLUtil.initSamlEngine();

        if (samlCallback.getAssertionElement() != null) {
            parseElement(samlCallback.getAssertionElement());
            fromDOM = true;
        } else {
            // If not then parse the SAMLCallback object
            parseCallback(samlCallback);
            fromDOM = false;
        }
    }

    public SAMLVersion getSAMLVersion() {
        if (saml1 != null) {
            return SAMLVersion.VERSION_11;
        }
        return SAMLVersion.VERSION_20;
    }

    public Element toDOM(Document doc) throws WSSecurityException {
        if (fromDOM && assertionElement != null) {
            parseElement(assertionElement);
            if (doc != null) {
                return (Element)doc.importNode(assertionElement, true);
            }
            return assertionElement;
        }
        assertionElement = OpenSAMLUtil.toDom(xmlObject, doc);
        return assertionElement;
    }

    /**
     * Method getId returns the id of this AssertionWrapper object.
     *
     * @return the id (type String) of this AssertionWrapper object.
     */
    public String getId() {
        String id = null;
        if (saml2 != null) {
            id = saml2.getID();
        } else if (saml1 != null) {
            id = saml1.getID();
        } else {
            logger.error("AssertionWrapper: unable to return ID - no saml assertion object");
        }
        if (id == null || id.length() == 0) {
            logger.error("AssertionWrapper: ID was null, seeting a new ID value");
            id = IDGenerator.generateID(null);
            if (saml2 != null) {
                saml2.setID(id);
            } else if (saml1 != null) {
                saml1.setID(id);
            }
        }
        return id;
    }

    public boolean isSigned() {
        if (saml2 != null) {
            return saml2.isSigned() || saml2.getSignature() != null;
        } else {
            return saml1.isSigned() || saml1.getSignature() != null;
        }
    }

    /**
     * Method getIssuerString returns the issuerString of this AssertionWrapper object.
     *
     * @return the issuerString (type String) of this AssertionWrapper object.
     */
    public String getIssuerString() {
        if (saml2 != null && saml2.getIssuer() != null) {
            return saml2.getIssuer().getValue();
        } else if (saml1 != null) {
            return saml1.getIssuer();
        }
        logger.error(
                "AssertionWrapper: unable to return Issuer string - no saml assertion "
                        + "object or issuer is null"
        );
        return null;
    }

    /**
     * Method setSignature sets the signature of this AssertionWrapper object.
     *
     * @param signature the signature of this AssertionWrapper object.
     */
    public void setSignature(Signature signature) {
        if (xmlObject instanceof SignableSAMLObject) {
            SignableSAMLObject signableObject = (SignableSAMLObject) xmlObject;
            signableObject.setSignature(signature);
            signableObject.releaseDOM();
            signableObject.releaseChildrenDOM(true);
        } else {
            logger.error("Attempt to sign an unsignable object " + xmlObject.getClass().getName());
        }
    }

    /**
     * Create an enveloped signature on the assertion that has been created.
     *
     * @param issuerKeyName     the Issuer KeyName to use with the issuerCrypto argument
     * @param issuerKeyPassword the Issuer Password to use with the issuerCrypto argument
     * @param issuerCrypto      the Issuer Crypto instance
     * @param sendKeyValue      whether to send the key value or not
     * @throws WSSecurityException
     */
    public void signAssertion(String issuerKeyName, String issuerKeyPassword,
                              Crypto issuerCrypto, boolean sendKeyValue)
            throws XMLSecurityException {

        signAssertion(issuerKeyName, issuerKeyPassword, issuerCrypto,
                sendKeyValue, defaultCanonicalizationAlgorithm,
                defaultRSASignatureAlgorithm);
    }

    /**
     * Create an enveloped signature on the assertion that has been created.
     *
     * @param issuerKeyName             the Issuer KeyName to use with the issuerCrypto argument
     * @param issuerKeyPassword         the Issuer Password to use with the issuerCrypto argument
     * @param issuerCrypto              the Issuer Crypto instance
     * @param sendKeyValue              whether to send the key value or not
     * @param canonicalizationAlgorithm the canonicalization algorithm to be used for signing
     * @param signatureAlgorithm        the signature algorithm to be used for signing
     * @throws WSSecurityException
     */
    public void signAssertion(String issuerKeyName, String issuerKeyPassword,
                              Crypto issuerCrypto, boolean sendKeyValue,
                              String canonicalizationAlgorithm, String signatureAlgorithm)
            throws XMLSecurityException {
        //
        // Create the signature
        //
        Signature signature = OpenSAMLUtil.buildSignature();
        signature.setCanonicalizationAlgorithm(canonicalizationAlgorithm);

        // prepare to sign the SAML token
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias(issuerKeyName);
        X509Certificate[] issuerCerts = issuerCrypto.getX509Certificates(cryptoType);
        if (issuerCerts == null) {
            throw new WSSecurityException(
                    "No issuer certs were found to sign the SAML Assertion using issuer name: "
                            + issuerKeyName
            );
        }

        String sigAlgo = signatureAlgorithm;
        String pubKeyAlgo = issuerCerts[0].getPublicKey().getAlgorithm();
        if (logger.isDebugEnabled()) {
            logger.debug("automatic sig algo detection: " + pubKeyAlgo);
        }
        if (pubKeyAlgo.equalsIgnoreCase("DSA")) {
            sigAlgo = defaultDSASignatureAlgorithm;
        }
        PrivateKey privateKey = null;
        try {
            privateKey = issuerCrypto.getPrivateKey(issuerKeyName, issuerKeyPassword);
        } catch (Exception ex) {
            throw new WSSecurityException(ex.getMessage(), ex);
        }

        signature.setSignatureAlgorithm(sigAlgo);

        BasicX509Credential signingCredential = new BasicX509Credential();
        signingCredential.setEntityCertificate(issuerCerts[0]);
        signingCredential.setPrivateKey(privateKey);

        signature.setSigningCredential(signingCredential);

        X509KeyInfoGeneratorFactory kiFactory = new X509KeyInfoGeneratorFactory();
        if (sendKeyValue) {
            kiFactory.setEmitPublicKeyValue(true);
        } else {
            kiFactory.setEmitEntityCertificate(true);
        }
        try {
            KeyInfo keyInfo = kiFactory.newInstance().generate(signingCredential);
            signature.setKeyInfo(keyInfo);
        } catch (org.opensaml.xml.security.SecurityException ex) {
            throw new WSSecurityException(
                    "Error generating KeyInfo from signing credential", ex
            );
        }

        // add the signature to the assertion
        setSignature(signature);
    }

    /**
     * Verify the signature of this assertion
     *
     * @throws ValidationException
     */
    public SAMLKeyInfo verifySignature(WSSSecurityProperties securityProperties) throws WSSecurityException {
        Signature sig = null;
        if (saml2 != null && saml2.getSignature() != null) {
            sig = saml2.getSignature();
        } else if (saml1 != null && saml1.getSignature() != null) {
            sig = saml1.getSignature();
        }

        KeyInfo keyInfo = sig.getKeyInfo();
        SAMLKeyInfo samlKeyInfo = getCredentialFromKeyInfo(keyInfo.getDOM(), securityProperties);

        if (samlKeyInfo == null) {
            throw new WSSecurityException(
                    WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity",
                    "cannot get certificate or key"
            );
        }

        SAMLSignatureProfileValidator validator = new SAMLSignatureProfileValidator();
        try {
            validator.validate(sig);
        } catch (ValidationException ex) {
            throw new WSSecurityException("SAML signature validation failed", ex);
        }

        BasicX509Credential credential = new BasicX509Credential();
        if (samlKeyInfo.getCerts() != null) {
            credential.setEntityCertificate(samlKeyInfo.getCerts()[0]);
        } else if (samlKeyInfo.getPublicKey() != null) {
            credential.setPublicKey(samlKeyInfo.getPublicKey());
        } else {
            throw new WSSecurityException(
                    WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity",
                    "cannot get certificate or key"
            );
        }
        SignatureValidator sigValidator = new SignatureValidator(credential);
        try {
            sigValidator.validate(sig);
        } catch (ValidationException ex) {
            throw new WSSecurityException("SAML signature validation failed", ex);
        }
        return samlKeyInfo;
    }

    /**
     * This method returns a SAMLKeyInfo corresponding to the credential found in the
     * KeyInfo (DOM Element) argument.
     *
     * @param keyInfoElement The KeyInfo as a DOM Element
     * @return The credential (as a SAMLKeyInfo object)
     * @throws WSSecurityException
     */
    private SAMLKeyInfo getCredentialFromKeyInfo(Element keyInfoElement, WSSSecurityProperties securityProperties) throws WSSecurityException {
        // First try to find an EncryptedKey or a BinarySecret via DOM
        Node node = keyInfoElement.getFirstChild();
        while (node != null) {
            if (Node.ELEMENT_NODE == node.getNodeType()) {
                QName el = new QName(node.getNamespaceURI(), node.getLocalName());
                if (el.equals(WSSConstants.TAG_xenc_EncryptedKey)) {
                    //todo:
                    /*
                    EncryptedKeyProcessor proc = new EncryptedKeyProcessor();
                    List<WSSecurityEngineResult> result =
                            proc.handleToken((Element) node, data, docInfo);
                    byte[] secret =
                            (byte[]) result.get(0).get(
                                    WSSecurityEngineResult.TAG_SECRET
                            );
                    return new SAMLKeyInfo(secret);
                    */
                    return null;
                } else if (el.equals(WSSConstants.TAG_wst_BinarySecret)) {
                    Text txt = (Text) node.getFirstChild();
                    return new SAMLKeyInfo(Base64.decodeBase64(txt.getData()));
                }
            }
            node = node.getNextSibling();
        }

        // Next marshal the KeyInfo DOM element into a javax KeyInfo object and get the
        // (public key) credential
        X509Certificate[] certs = null;
        KeyInfoFactory keyInfoFactory = KeyInfoFactory.getInstance("DOM");
        XMLStructure keyInfoStructure = new DOMStructure(keyInfoElement);

        try {
            javax.xml.crypto.dsig.keyinfo.KeyInfo keyInfo =
                    keyInfoFactory.unmarshalKeyInfo(keyInfoStructure);
            List<?> list = keyInfo.getContent();

            for (int i = 0; i < list.size(); i++) {
                XMLStructure xmlStructure = (XMLStructure) list.get(i);
                if (xmlStructure instanceof KeyValue) {
                    PublicKey publicKey = ((KeyValue) xmlStructure).getPublicKey();
                    return new SAMLKeyInfo(publicKey);
                } else if (xmlStructure instanceof X509Data) {
                    List<?> x509Data = ((X509Data) xmlStructure).getContent();
                    for (int j = 0; j < x509Data.size(); j++) {
                        Object x509obj = x509Data.get(j);
                        if (x509obj instanceof X509Certificate) {
                            certs = new X509Certificate[1];
                            certs[0] = (X509Certificate) x509obj;
                            return new SAMLKeyInfo(certs);
                        } else if (x509obj instanceof X509IssuerSerial) {
                            if (securityProperties.getSignatureVerificationCrypto() == null) {
                                throw new WSSecurityException(
                                        WSSecurityException.ErrorCode.FAILURE, "noSigCryptoFile"
                                );
                            }
                            CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ISSUER_SERIAL);
                            cryptoType.setIssuerSerial(
                                    ((X509IssuerSerial) x509obj).getIssuerName(), ((X509IssuerSerial) x509obj).getSerialNumber()
                            );
                            certs = securityProperties.getSignatureVerificationCrypto().getX509Certificates(cryptoType);
                            if (certs == null || certs.length < 1) {
                                throw new WSSecurityException(
                                        WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity",
                                        "cannot get certificate or key"
                                );
                            }
                            return new SAMLKeyInfo(certs);
                        }
                    }
                }
            }
        } catch (Exception ex) {
            throw new WSSecurityException(
                    WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity",
                    ex, "cannot get certificate or key"
            );
        }
        return null;
    }

    /**
     * This method parses the KeyInfo of the Subject for the holder-of-key confirmation
     * method, as required by the SAML Token spec. It then stores the SAMLKeyInfo object that
     * has been obtained for future processing by the SignatureProcessor.
     *
     * @throws WSSecurityException
     */
    public SAMLKeyInfo parseHOKSubject(WSSSecurityProperties securityProperties) throws XMLSecurityException {
        String confirmMethod = null;
        List<String> methods = getConfirmationMethods();
        if (methods != null && methods.size() > 0) {
            confirmMethod = methods.get(0);
        }
        SAMLKeyInfo samlKeyInfo = null;
        if (OpenSAMLUtil.isMethodHolderOfKey(confirmMethod)) {

            if (saml2 != null) {
                samlKeyInfo = getCredentialFromSubject(saml2, securityProperties);
            } else if (saml1 != null) {
                samlKeyInfo = getCredentialFromSubject(saml1, securityProperties);
            }

            if (samlKeyInfo == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "noKeyInSAMLToken");
            }
            // The assertion must have been signed for HOK
            if (!isSigned()) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity");
            }
        }
        return samlKeyInfo;
    }

    /**
     * Verify trust in the signature of a signed Assertion. This method is separate so that
     * the user can override if if they want.
     *
     * @return A Credential instance
     * @throws WSSecurityException
     */
    public void verifySignedAssertion(SAMLKeyInfo samlKeyInfo, WSSSecurityProperties securityProperties) throws XMLSecurityException {
        validate(samlKeyInfo.getCerts(), samlKeyInfo.getPublicKey(), securityProperties);
    }

    /**
     * Validate the credential argument. It must contain a non-null X509Certificate chain
     * or a PublicKey. A Crypto implementation is also required to be set.
     * <p/>
     * This implementation first attempts to verify trust on the certificate (chain). If
     * this is not successful, then it will attempt to verify trust on the Public Key.
     *
     * @throws WSSecurityException on a failed validation
     */
    protected void validate(X509Certificate[] certs, PublicKey publicKey, WSSSecurityProperties securityProperties) throws XMLSecurityException {
        Crypto crypto = securityProperties.getSignatureVerificationCrypto();
        if (crypto == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "noSigCryptoFile");
        }

        if (certs != null && certs.length > 0) {
            validateCertificates(certs);
            boolean trust = false;
            if (certs.length == 1) {
                trust = verifyTrustInCert(certs[0], crypto);
            } else {
                trust = verifyTrustInCerts(certs, crypto);
            }
            if (trust) {
                return;
            }
        }
        if (publicKey != null) {
            boolean trust = validatePublicKey(publicKey, crypto);
            if (trust) {
                return;
            }
        }
        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
    }

    /**
     * Validate the certificates by checking the validity of each cert
     *
     * @throws WSSecurityException
     */
    protected void validateCertificates(X509Certificate[] certificates)
            throws WSSecurityException {
        try {
            for (int i = 0; i < certificates.length; i++) {
                certificates[i].checkValidity();
            }
        } catch (CertificateExpiredException e) {
            throw new WSSecurityException(
                    WSSecurityException.ErrorCode.FAILED_CHECK, "invalidCert", e
            );
        } catch (CertificateNotYetValidException e) {
            throw new WSSecurityException(
                    WSSecurityException.ErrorCode.FAILED_CHECK, "invalidCert", e
            );
        }
    }

    /**
     * Method getConfirmationMethods returns the confirmationMethods of this
     * AssertionWrapper object.
     *
     * @return the confirmationMethods of this AssertionWrapper object.
     */
    public List<String> getConfirmationMethods() {
        List<String> methods = new ArrayList<String>();
        if (saml2 != null) {
            org.opensaml.saml2.core.Subject subject = saml2.getSubject();
            List<org.opensaml.saml2.core.SubjectConfirmation> confirmations =
                    subject.getSubjectConfirmations();
            for (org.opensaml.saml2.core.SubjectConfirmation confirmation : confirmations) {
                methods.add(confirmation.getMethod());
            }
        } else if (saml1 != null) {
            List<SubjectStatement> subjectStatements = new ArrayList<SubjectStatement>();
            subjectStatements.addAll(saml1.getSubjectStatements());
            subjectStatements.addAll(saml1.getAuthenticationStatements());
            subjectStatements.addAll(saml1.getAttributeStatements());
            subjectStatements.addAll(saml1.getAuthorizationDecisionStatements());
            for (SubjectStatement subjectStatement : subjectStatements) {
                Subject subject = subjectStatement.getSubject();
                if (subject != null) {
                    SubjectConfirmation confirmation = subject.getSubjectConfirmation();
                    if (confirmation != null) {
                        XMLObject data = confirmation.getSubjectConfirmationData();
                        if (data instanceof ConfirmationMethod) {
                            ConfirmationMethod method = (ConfirmationMethod) data;
                            methods.add(method.getConfirmationMethod());
                        }
                        List<ConfirmationMethod> confirmationMethods =
                                confirmation.getConfirmationMethods();
                        for (ConfirmationMethod confirmationMethod : confirmationMethods) {
                            methods.add(confirmationMethod.getConfirmationMethod());
                        }
                    }
                }
            }
        }
        return methods;
    }

    /**
     * Parse a SAML Assertion to obtain a SAMLKeyInfo object from
     * the Subject of the assertion
     *
     * @return a SAMLKeyInfo object
     * @throws WSSecurityException
     */
    public SAMLKeyInfo getCredentialFromSubject(WSSSecurityProperties securityProperties) throws XMLSecurityException {
        if (this.saml2 != null) {
            return getCredentialFromSubject(this.saml2, securityProperties);
        } else {
            return getCredentialFromSubject(this.saml1, securityProperties);
        }
    }

    /**
     * Get the SAMLKeyInfo object corresponding to the credential stored in the Subject of a
     * SAML 1.1 assertion
     *
     * @param assertion The SAML 1.1 assertion
     * @return The SAMLKeyInfo object obtained from the Subject
     * @throws WSSecurityException
     */
    public SAMLKeyInfo getCredentialFromSubject(org.opensaml.saml1.core.Assertion assertion, WSSSecurityProperties securityProperties) throws XMLSecurityException {
        // First try to get the credential from a CallbackHandler
        WSPasswordCallback passwordCallback = new WSPasswordCallback(assertion.getID(), WSPasswordCallback.Usage.SECRET_KEY);
        WSSUtils.doSecretKeyCallback(securityProperties.getCallbackHandler(), passwordCallback, assertion.getID());
        final byte[] key = passwordCallback.getKey();
        if (key != null && key.length > 0) {
            return new SAMLKeyInfo(key);
        }

        for (org.opensaml.saml1.core.Statement stmt : assertion.getStatements()) {
            org.opensaml.saml1.core.Subject samlSubject = null;
            if (stmt instanceof org.opensaml.saml1.core.AttributeStatement) {
                org.opensaml.saml1.core.AttributeStatement attrStmt =
                        (org.opensaml.saml1.core.AttributeStatement) stmt;
                samlSubject = attrStmt.getSubject();
            } else if (stmt instanceof org.opensaml.saml1.core.AuthenticationStatement) {
                org.opensaml.saml1.core.AuthenticationStatement authStmt =
                        (org.opensaml.saml1.core.AuthenticationStatement) stmt;
                samlSubject = authStmt.getSubject();
            } else {
                org.opensaml.saml1.core.AuthorizationDecisionStatement authzStmt =
                        (org.opensaml.saml1.core.AuthorizationDecisionStatement) stmt;
                samlSubject = authzStmt.getSubject();
            }

            if (samlSubject == null) {
                throw new WSSecurityException(
                        WSSecurityException.ErrorCode.FAILURE, "invalidSAMLToken",
                        "for Signature (no Subject)"
                );
            }

            Element sub = samlSubject.getSubjectConfirmation().getDOM();
            Element keyInfoElement =
                    XMLUtils.getDirectChildElement(sub, WSSConstants.TAG_dsig_KeyInfo.getLocalPart(), WSSConstants.TAG_dsig_KeyInfo.getNamespaceURI());
            if (keyInfoElement != null) {
                return getCredentialFromKeyInfo(keyInfoElement, securityProperties);
            }
        }

        return null;
    }


    /**
     * Get the SAMLKeyInfo object corresponding to the credential stored in the Subject of a
     * SAML 2 assertion
     *
     * @param assertion The SAML 2 assertion
     * @return The SAMLKeyInfo object obtained from the Subject
     * @throws WSSecurityException
     */
    public SAMLKeyInfo getCredentialFromSubject(org.opensaml.saml2.core.Assertion assertion, WSSSecurityProperties securityProperties) throws XMLSecurityException {
        // First try to get the credential from a CallbackHandler
        WSPasswordCallback passwordCallback = new WSPasswordCallback(assertion.getID(), WSPasswordCallback.Usage.SECRET_KEY);
        WSSUtils.doSecretKeyCallback(securityProperties.getCallbackHandler(), passwordCallback, assertion.getID());
        final byte[] key = passwordCallback.getKey();
        if (key != null && key.length > 0) {
            return new SAMLKeyInfo(key);
        }

        org.opensaml.saml2.core.Subject samlSubject = assertion.getSubject();
        if (samlSubject == null) {
            throw new WSSecurityException(
                    WSSecurityException.ErrorCode.FAILURE, "invalidSAMLToken",
                    "for Signature (no Subject)"
            );
        }
        List<org.opensaml.saml2.core.SubjectConfirmation> subjectConfList =
                samlSubject.getSubjectConfirmations();
        for (org.opensaml.saml2.core.SubjectConfirmation subjectConfirmation : subjectConfList) {
            SubjectConfirmationData subjConfData =
                    subjectConfirmation.getSubjectConfirmationData();
            Element sub = subjConfData.getDOM();
            Element keyInfoElement =
                    XMLUtils.getDirectChildElement(sub, WSSConstants.TAG_dsig_KeyInfo.getLocalPart(), WSSConstants.TAG_dsig_KeyInfo.getNamespaceURI());
            if (keyInfoElement != null) {
                return getCredentialFromKeyInfo(keyInfoElement, securityProperties);
            }
        }

        return null;
    }

    /**
     * Check to see if the certificate argument is in the keystore
     *
     * @param crypto The Crypto instance to use
     * @param cert   The certificate to check
     * @return true if cert is in the keystore
     * @throws WSSecurityException
     */
    protected boolean isCertificateInKeyStore(Crypto crypto, X509Certificate cert) throws XMLSecurityException {
        String issuerString = cert.getIssuerX500Principal().getName();
        BigInteger issuerSerial = cert.getSerialNumber();

        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ISSUER_SERIAL);
        cryptoType.setIssuerSerial(issuerString, issuerSerial);
        X509Certificate[] foundCerts = crypto.getX509Certificates(cryptoType);

        //
        // If a certificate has been found, the certificates must be compared
        // to ensure against phony DNs (compare encoded form including signature)
        //
        if (foundCerts != null && foundCerts[0] != null && foundCerts[0].equals(cert)) {
            if (logger.isDebugEnabled()) {
                logger.debug(
                        "Direct trust for certificate with " + cert.getSubjectX500Principal().getName()
                );
            }
            return true;
        }
        if (logger.isDebugEnabled()) {
            logger.debug(
                    "No certificate found for subject from issuer with " + issuerString
                            + " (serial " + issuerSerial + ")"
            );
        }
        return false;
    }

    /**
     * Evaluate whether a given certificate should be trusted.
     * <p/>
     * Policy used in this implementation:
     * 1. Search the keystore for the transmitted certificate
     * 2. Search the keystore for a connection to the transmitted certificate
     * (that is, search for certificate(s) of the issuer of the transmitted certificate
     * 3. Verify the trust path for those certificates found because the search for the issuer
     * might be fooled by a phony DN (String!)
     *
     * @param cert   the certificate that should be validated against the keystore
     * @param crypto A crypto instance to use for trust validation
     * @return true if the certificate is trusted, false if not
     * @throws WSSecurityException
     */
    protected boolean verifyTrustInCert(X509Certificate cert, Crypto crypto) throws XMLSecurityException {
        String subjectString = cert.getSubjectX500Principal().getName();
        String issuerString = cert.getIssuerX500Principal().getName();
        BigInteger issuerSerial = cert.getSerialNumber();

        if (logger.isDebugEnabled()) {
            logger.debug("Transmitted certificate has subject " + subjectString);
            logger.debug(
                    "Transmitted certificate has issuer " + issuerString + " (serial "
                            + issuerSerial + ")"
            );
        }

        //
        // FIRST step - Search the keystore for the transmitted certificate
        //
        if (isCertificateInKeyStore(crypto, cert)) {
            return true;
        }

        //
        // SECOND step - Search for the issuer cert (chain) of the transmitted certificate in the
        // keystore or the truststore
        //
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias(issuerString);
        X509Certificate[] foundCerts = crypto.getX509Certificates(cryptoType);

        // If the certs have not been found, the issuer is not in the keystore/truststore
        // As a direct result, do not trust the transmitted certificate
        if (foundCerts == null || foundCerts.length < 1) {
            if (logger.isDebugEnabled()) {
                logger.debug(
                        "No certs found in keystore for issuer " + issuerString
                                + " of certificate for " + subjectString
                );
            }
            return false;
        }

        //
        // THIRD step
        // Check the certificate trust path for the issuer cert chain
        //
        if (logger.isDebugEnabled()) {
            logger.debug(
                    "Preparing to validate certificate path for issuer " + issuerString
            );
        }
        //
        // Form a certificate chain from the transmitted certificate
        // and the certificate(s) of the issuer from the keystore/truststore
        //
        X509Certificate[] x509certs = new X509Certificate[foundCerts.length + 1];
        x509certs[0] = cert;
        System.arraycopy(foundCerts, 0, x509certs, 1, foundCerts.length);

        //
        // Use the validation method from the crypto to check whether the subjects'
        // certificate was really signed by the issuer stated in the certificate
        //
        if (crypto.verifyTrust(x509certs)) {
            if (logger.isDebugEnabled()) {
                logger.debug(
                        "Certificate path has been verified for certificate with subject "
                                + subjectString
                );
            }
            return true;
        }

        if (logger.isDebugEnabled()) {
            logger.debug(
                    "Certificate path could not be verified for certificate with subject "
                            + subjectString
            );
        }
        return false;
    }

    /**
     * Evaluate whether the given certificate chain should be trusted.
     *
     * @param certificates the certificate chain that should be validated against the keystore
     * @return true if the certificate chain is trusted, false if not
     * @throws WSSecurityException
     */
    protected boolean verifyTrustInCerts(X509Certificate[] certificates, Crypto crypto) throws XMLSecurityException {
        //
        // Use the validation method from the crypto to check whether the subjects'
        // certificate was really signed by the issuer stated in the certificate
        //
        if (certificates != null && certificates.length > 0
                && crypto.verifyTrust(certificates)) {
            return true;
        }
        return false;
    }

    /**
     * Validate a public key
     *
     * @throws WSSecurityException
     */
    protected boolean validatePublicKey(PublicKey publicKey, Crypto crypto) throws XMLSecurityException {
        return crypto.verifyTrust(publicKey);
    }

    /**
     * Parse the DOM Element into Opensaml objects.
     */
    private void parseElement(Element element) throws WSSecurityException {
        this.xmlObject = OpenSAMLUtil.fromDom(element);
        if (xmlObject instanceof org.opensaml.saml1.core.Assertion) {
            this.saml1 = (org.opensaml.saml1.core.Assertion) xmlObject;
        } else if (xmlObject instanceof org.opensaml.saml2.core.Assertion) {
            this.saml2 = (org.opensaml.saml2.core.Assertion) xmlObject;
        } else {
            logger.error(
                    "AssertionWrapper: found unexpected type "
                            + (xmlObject != null ? xmlObject.getClass().getName() : xmlObject)
            );
        }

        assertionElement = element;
    }

    /**
     * Parse a SAMLCallback object to create a SAML Assertion
     */
    private void parseCallback(
            SAMLCallback samlCallback
    ) throws WSSecurityException, XMLSecurityException {
        SAMLVersion samlVersion = samlCallback.getSamlVersion();

        String issuer = samlCallback.getIssuer();
        if (samlVersion.equals(SAMLVersion.VERSION_11)) {
            // Build a SAML v1.1 assertion
            saml1 = SAML1ComponentBuilder.createSamlv1Assertion(issuer);

            try {
                // Process the SAML authentication statement(s)
                List<AuthenticationStatement> authenticationStatements =
                        SAML1ComponentBuilder.createSamlv1AuthenticationStatement(
                                samlCallback.getAuthenticationStatementData()
                        );
                saml1.getAuthenticationStatements().addAll(authenticationStatements);

                // Process the SAML attribute statement(s)            
                List<AttributeStatement> attributeStatements =
                        SAML1ComponentBuilder.createSamlv1AttributeStatement(
                                samlCallback.getAttributeStatementData()
                        );
                saml1.getAttributeStatements().addAll(attributeStatements);

                // Process the SAML authorization decision statement(s)
                List<AuthorizationDecisionStatement> authDecisionStatements =
                        SAML1ComponentBuilder.createSamlv1AuthorizationDecisionStatement(
                                samlCallback.getAuthDecisionStatementData()
                        );
                saml1.getAuthorizationDecisionStatements().addAll(authDecisionStatements);

                // Build the complete assertion
                org.opensaml.saml1.core.Conditions conditions =
                        SAML1ComponentBuilder.createSamlv1Conditions(samlCallback.getConditions());
                saml1.setConditions(conditions);
            } catch (org.opensaml.xml.security.SecurityException ex) {
                throw new WSSecurityException(
                        "Error generating KeyInfo from signing credential", ex
                );
            }

            // Set the OpenSaml2 XMLObject instance
            xmlObject = saml1;

        } else if (samlVersion.equals(SAMLVersion.VERSION_20)) {
            // Build a SAML v2.0 assertion
            saml2 = SAML2ComponentBuilder.createAssertion();
            Issuer samlIssuer = SAML2ComponentBuilder.createIssuer(issuer);

            // Authn Statement(s)
            List<AuthnStatement> authnStatements =
                    SAML2ComponentBuilder.createAuthnStatement(
                            samlCallback.getAuthenticationStatementData()
                    );
            saml2.getAuthnStatements().addAll(authnStatements);

            // Attribute statement(s)
            List<org.opensaml.saml2.core.AttributeStatement> attributeStatements =
                    SAML2ComponentBuilder.createAttributeStatement(
                            samlCallback.getAttributeStatementData()
                    );
            saml2.getAttributeStatements().addAll(attributeStatements);

            // AuthzDecisionStatement(s)
            List<AuthzDecisionStatement> authDecisionStatements =
                    SAML2ComponentBuilder.createAuthorizationDecisionStatement(
                            samlCallback.getAuthDecisionStatementData()
                    );
            saml2.getAuthzDecisionStatements().addAll(authDecisionStatements);

            // Build the SAML v2.0 assertion
            saml2.setIssuer(samlIssuer);

            try {
                org.opensaml.saml2.core.Subject subject =
                        SAML2ComponentBuilder.createSaml2Subject(samlCallback.getSubject());
                saml2.setSubject(subject);
            } catch (org.opensaml.xml.security.SecurityException ex) {
                throw new WSSecurityException(
                        "Error generating KeyInfo from signing credential", ex
                );
            }

            org.opensaml.saml2.core.Conditions conditions =
                    SAML2ComponentBuilder.createConditions(samlCallback.getConditions());
            saml2.setConditions(conditions);

            // Set the OpenSaml2 XMLObject instance
            xmlObject = saml2;
        }
    }

}
