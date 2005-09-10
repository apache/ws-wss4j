/*
 * Copyright  2003-2004 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.apache.ws.security.message;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.SOAPConstants;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSDocInfoStore;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.message.token.BinarySecurity;
import org.apache.ws.security.message.token.PKIPathSecurity;
import org.apache.ws.security.message.token.Reference;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.message.token.X509Security;
import org.apache.ws.security.transform.STRTransform;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.keys.content.x509.XMLX509Certificate;
import org.apache.xml.security.keys.content.x509.XMLX509IssuerSerial;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.transforms.TransformationException;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.transforms.params.InclusiveNamespaces;
import org.apache.xml.security.utils.XMLUtils;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.algorithms.SignatureAlgorithm;

import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLException;
import org.opensaml.SAMLObject;
import org.opensaml.SAMLSubject;
import org.opensaml.SAMLSubjectStatement;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NamedNodeMap;

import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.Vector;
import java.util.Set;
import java.util.HashSet;

/**
 * Signs a SOAP envelope according to WS Specification, X509 profile, and adds
 * the signature data.
 *
 * @author Davanum Srinivas (dims@yahoo.com)
 * @author Werner Dittmann (Werner.Dittman@siemens.com)
 */
public class WSSignEnvelope extends WSBaseMessage {

    private static Log log = LogFactory.getLog(WSSignEnvelope.class.getName());

    private static Log tlog = LogFactory.getLog("org.apache.ws.security.TIME");

    protected boolean useSingleCert = true;

    protected String sigAlgo = null;

    protected String canonAlgo = Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS;

    protected WSSAddUsernameToken usernameToken = null;

    protected byte[] signatureValue = null;

    /**
     * Constructor.
     */
    public WSSignEnvelope() {
    }

    /**
     * Constructor.
     *
     * @param actor The actor name of the <code>wsse:Security</code> header
     */
    public WSSignEnvelope(String actor) {
        super(actor);
    }

    /**
     * Constructor.
     *
     * @param actor The actor name of the <code>wsse:Security</code> header
     * @param mu    Set <code>mustUnderstand</code> to true or false
     */
    public WSSignEnvelope(String actor, boolean mu) {
        super(actor, mu);
    }

    /**
     * set the single cert flag.
     *
     * @param useSingleCert
     */
    public void setUseSingleCertificate(boolean useSingleCert) {
        this.useSingleCert = useSingleCert;
    }

    /**
     * Get the single cert flag.
     *
     * @return
     */
    public boolean isUseSingleCertificate() {
        return this.useSingleCert;
    }

    /**
     * Set the name of the signature encryption algorithm to use.
     * 
     * If the algorithm is not set then Triple RSA is used. Refer to WSConstants
     * which algorithms are supported.
     * 
     * @param algo
     *            Is the name of the signature algorithm
     * @see WSConstants#RSA
     * @see WSConstants#DSA
     */
    public void setSignatureAlgorithm(String algo) {
        sigAlgo = algo;
    }

    /**
     * Get the name of the signature algorithm that is being used.
     * 
     * If the algorithm is not set then RSA is default.
     *
     * @return the identifier URI of the signature algorithm
     */
    public String getSignatureAlgorithm() {
        return sigAlgo;
    }

    /**
     * Set the canonicalization method to use.
     * 
     * If the canonicalization method is not set then the recommended Exclusive
     * XML Canonicalization is used by default Refer to WSConstants which
     * algorithms are supported.
     * 
     * @param algo
     *            Is the name of the signature algorithm
     * @see WSConstants#C14N_OMIT_COMMENTS
     * @see WSConstants#C14N_WITH_COMMENTS
     * @see WSConstants#C14N_EXCL_OMIT_COMMENTS
     * @see WSConstants#C14N_EXCL_WITH_COMMENTS
     */
    public void setSigCanonicalization(String algo) {
        canonAlgo = algo;
    }

    /**
     * Get the canonicalization method.
     * 
     * If the canonicalization method was not set then Exclusive XML
     * Canonicalization is used by default.
     * 
     * @return
     */
    public String getSigCanonicalization() {
        return canonAlgo;
    }

    /**
     * @param usernameToken The usernameToken to set.
     */
    public void setUsernameToken(WSSAddUsernameToken usernameToken) {
        this.usernameToken = usernameToken;
    }

    /**
     * @return Returns the signatureValue.
     */
    public byte[] getSignatureValue() {
        return signatureValue;
    }

    /**
     * Builds a signed soap envelope. 
     * 
     * The method first gets an appropriate
     * security header. According to the defined parameters for certificate
     * handling the signature elements are constructed and inserted into the
     * <code>wsse:Signature</code>
     *
     * @param doc    The unsigned SOAP envelope as <code>Document</code>
     * @param crypto An instance of the Crypto API to handle keystore and
     *               certificates
     * @return A signed SOAP envelope as <code>Document</code>
     * @throws WSSecurityException
     */
    public Document build(Document doc, Crypto crypto)
            throws WSSecurityException {
        doDebug = log.isDebugEnabled();

        long t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0;
        if (tlog.isDebugEnabled()) {
            t0 = System.currentTimeMillis();
        }
        if (doDebug) {
            log.debug("Beginning signing...");
        }

        /*
         * Gather some info about the document to process and store it for
         * retrival
         */
        WSDocInfo wsDocInfo = new WSDocInfo(doc.hashCode());
        wsDocInfo.setCrypto(crypto);

        Element envelope = doc.getDocumentElement();
        SOAPConstants soapConstants = WSSecurityUtil.getSOAPConstants(envelope);

        Element securityHeader = insertSecurityHeader(doc);

        // Set the id of the elements to be used as digest source
        // String id = setBodyID(doc);
        String certUri = null;
        X509Certificate[] certs = null;
        if (keyIdentifierType != WSConstants.UT_SIGNING) {
            certs = crypto.getCertificates(user);
            if (certs == null || certs.length <= 0) {
                throw new WSSecurityException(WSSecurityException.FAILURE,
                        "invalidX509Data", new Object[] { "for Signature" });
            }
            certUri = "CertId-" + certs[0].hashCode();
            if (sigAlgo == null) {
                String pubKeyAlgo = certs[0].getPublicKey().getAlgorithm();
                log.debug("automatic sig algo detection: " + pubKeyAlgo);
                if (pubKeyAlgo.equalsIgnoreCase("DSA")) {
                    sigAlgo = XMLSignature.ALGO_ID_SIGNATURE_DSA;
                } else if (pubKeyAlgo.equalsIgnoreCase("RSA")) {
                    sigAlgo = XMLSignature.ALGO_ID_SIGNATURE_RSA;
                } else {
                    throw new WSSecurityException(
                            WSSecurityException.FAILURE,
                            "invalidX509Data",
                            new Object[] { "for Signature - unkown public key Algo" });
                }
            }
        }
        XMLSignature sig = null;

        if (canonAlgo.equals(WSConstants.C14N_EXCL_OMIT_COMMENTS)) {
            Element canonElem = XMLUtils.createElementInSignatureSpace(doc,
                    Constants._TAG_CANONICALIZATIONMETHOD);

            canonElem.setAttributeNS(null, Constants._ATT_ALGORITHM, canonAlgo);

            if (wssConfig.isWsiBSPCompliant()) {
                Set prefixes = getInclusivePrefixes(securityHeader, false);

                InclusiveNamespaces inclusiveNamespaces = new InclusiveNamespaces(
                        doc, prefixes);

                canonElem.appendChild(inclusiveNamespaces.getElement());
            }

            try {
                SignatureAlgorithm signatureAlgorithm = new SignatureAlgorithm(
                        doc, sigAlgo);
                sig = new XMLSignature(doc, null, signatureAlgorithm
                        .getElement(), canonElem);
            } catch (XMLSecurityException e) {
                log.error("", e);
                throw new WSSecurityException(
                        WSSecurityException.FAILED_SIGNATURE, "noXMLSig");
            }
        } else {
            try {
                sig = new XMLSignature(doc, null, sigAlgo, canonAlgo);
            } catch (XMLSecurityException e) {
                log.error("", e);
                throw new WSSecurityException(
                        WSSecurityException.FAILED_SIGNATURE, "noXMLSig");
            }
        }
        /*
         * If we don't generate a new Transforms for each addDocument here, then
         * only the last Transforms is put into the according ds:Reference
         * element, i.e. the first ds:Reference does not contain a Transforms
         * element. Thus the verification fails (somehow)
         */

        KeyInfo info = sig.getKeyInfo();
        String keyInfoUri = "KeyId-" + info.hashCode();
        info.setId(keyInfoUri);

        SecurityTokenReference secRef = new SecurityTokenReference(doc);
        String strUri = "STRId-" + secRef.hashCode();
        secRef.setID(strUri);

        if (tlog.isDebugEnabled()) {
            t1 = System.currentTimeMillis();
        }

        if (parts == null) {
            parts = new Vector();
            WSEncryptionPart encP = new WSEncryptionPart(soapConstants
                    .getBodyQName().getLocalPart(), soapConstants
                    .getEnvelopeURI(), "Content");
            parts.add(encP);
        }

        Transforms transforms = null;

        for (int part = 0; part < parts.size(); part++) {
            WSEncryptionPart encPart = (WSEncryptionPart) parts.get(part);
            
            String idToSign = encPart.getId();
            
            String elemName = encPart.getName();
            String nmSpace = encPart.getNamespace();
 
            /*
             * Set up the elements to sign. There are two resevered element
             * names: "Token" and "STRTransform" "Token": Setup the Signature to
             * either sign the information that points to the security token or
             * the token itself. If its a direct reference sign the token,
             * otherwise sign the KeyInfo Element. "STRTransform": Setup the
             * ds:Reference to use STR Transform
             *
             */
            try {
                if (idToSign != null) {
                    Element toSignById = WSSecurityUtil.getElementByWsuId(doc, "#"+idToSign);
                    transforms = new Transforms(doc);
                    transforms
                            .addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
                    if (wssConfig.isWsiBSPCompliant()) {
                        transforms.item(0).getElement().appendChild(
                                new InclusiveNamespaces(doc,
                                        getInclusivePrefixes(toSignById))
                                        .getElement());
                    }
                    sig.addDocument("#" + idToSign, transforms);
                }
                else if (elemName.equals("Token")) {
                    transforms = new Transforms(doc);
                    transforms
                            .addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
                    if (keyIdentifierType == WSConstants.BST_DIRECT_REFERENCE) {
                        if (wssConfig.isWsiBSPCompliant()) {
                            transforms
                                    .item(0)
                                    .getElement()
                                    .appendChild(
                                            new InclusiveNamespaces(
                                                    doc,
                                                    getInclusivePrefixes(securityHeader))
                                                    .getElement());
                        }
                        sig.addDocument("#" + certUri, transforms);
                    } else {
                        if (wssConfig.isWsiBSPCompliant()) {
                            transforms.item(0).getElement().appendChild(
                                    new InclusiveNamespaces(doc,
                                            getInclusivePrefixes(info
                                                    .getElement()))
                                            .getElement());
                        }
                        sig.addDocument("#" + keyInfoUri, transforms);
                    }
                } else if (elemName.equals("STRTransform")) { // STRTransform
                    Element ctx = createSTRParameter(doc);
                    transforms = new Transforms(doc);
                    transforms.addTransform(
                            STRTransform.implementedTransformURI, ctx);
                    sig.addDocument("#" + strUri, transforms);
                } else if (elemName.equals("Assertion")) { // Assertion
                    // Make the AssertionID the wsu:Id and the signature reference the same 
                    SAMLAssertion assertion;

                    Element assertionElement = (Element) WSSecurityUtil
                            .findElement(envelope, elemName, nmSpace);

                    try {
                        assertion = new SAMLAssertion(assertionElement);
                    } catch (Exception e1) {
                        log.error(e1);
                        throw new WSSecurityException(
                                WSSecurityException.FAILED_SIGNATURE,
                                "noXMLSig", null, e1);
                    }

                    Element body = (Element) WSSecurityUtil.findElement(
                            envelope, elemName, nmSpace);
                    if (body == null) {
                        throw new WSSecurityException(
                                WSSecurityException.FAILURE, "noEncElement",
                                new Object[] { nmSpace + ", " + elemName });
                    }
                    transforms = new Transforms(doc);
                    transforms
                            .addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
                    if (wssConfig.isWsiBSPCompliant()) {
                        transforms.item(0).getElement().appendChild(
                                new InclusiveNamespaces(doc,
                                        getInclusivePrefixes(body))
                                        .getElement());
                    }
                    String prefix = WSSecurityUtil.setNamespace(body,
                            WSConstants.WSU_NS, WSConstants.WSU_PREFIX);
                    body.setAttributeNS(WSConstants.WSU_NS, prefix + ":Id",
                            assertion.getId());
                    sig.addDocument("#" + assertion.getId(), transforms);

                } else {
                    Element body = (Element) WSSecurityUtil.findElement(
                            envelope, elemName, nmSpace);
                    if (body == null) {
                        throw new WSSecurityException(
                                WSSecurityException.FAILURE, "noEncElement",
                                new Object[] { nmSpace + ", " + elemName });
                    }
                    transforms = new Transforms(doc);
                    transforms
                            .addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
                    if (wssConfig.isWsiBSPCompliant()) {
                        transforms.item(0).getElement().appendChild(
                                new InclusiveNamespaces(doc,
                                        getInclusivePrefixes(body))
                                        .getElement());
                    }
                    sig.addDocument("#" + setWsuId(body), transforms);
                }
            } catch (TransformationException e1) {
                throw new WSSecurityException(
                        WSSecurityException.FAILED_SIGNATURE, "noXMLSig", null,
                        e1);
            } catch (XMLSignatureException e1) {
                throw new WSSecurityException(
                        WSSecurityException.FAILED_SIGNATURE, "noXMLSig", null,
                        e1);
            }
        }

        sig.addResourceResolver(EnvelopeIdResolver.getInstance());

        WSSecurityUtil.prependChildElement(doc, securityHeader, sig
                .getElement(), false);
        if (tlog.isDebugEnabled()) {
            t2 = System.currentTimeMillis();
        }

        byte[] secretKey = null;
        switch (keyIdentifierType) {
        case WSConstants.BST_DIRECT_REFERENCE:
            Reference ref = new Reference(doc);
            ref.setURI("#" + certUri);
            BinarySecurity bstToken = null;
            if (!useSingleCert) {
                bstToken = new PKIPathSecurity(doc);
                ((PKIPathSecurity) bstToken).setX509Certificates(certs, false,
                        crypto);
            } else {
                bstToken = new X509Security(doc);
                ((X509Security) bstToken).setX509Certificate(certs[0]);
            }
            ref.setValueType(bstToken.getValueType());
            secRef.setReference(ref);
            bstToken.setID(certUri);
            WSSecurityUtil.prependChildElement(doc, securityHeader, bstToken
                    .getElement(), false);
            wsDocInfo.setBst(bstToken.getElement());
            break;

        case WSConstants.ISSUER_SERIAL:
            XMLX509IssuerSerial data = new XMLX509IssuerSerial(doc, certs[0]);
            X509Data x509Data = new X509Data(doc); 
            x509Data.add(data);
            secRef.setX509IssuerSerial(x509Data);
            break;

        case WSConstants.X509_KEY_IDENTIFIER:
            secRef.setKeyIdentifier(certs[0]);
            break;

        case WSConstants.SKI_KEY_IDENTIFIER:
            secRef.setKeyIdentifierSKI(certs[0], crypto);
            break;

        case WSConstants.UT_SIGNING:
            Reference refUt = new Reference(doc);
            refUt.setValueType(WSConstants.USERNAMETOKEN_NS + "#UsernameToken");
            String utId = usernameToken.getId();
            if (utId == null) {
                utId = "usernameTokenId-" + usernameToken.hashCode();
                usernameToken.setId(utId);
            }
            refUt.setURI("#" + utId);
            secRef.setReference(refUt);
            secretKey = usernameToken.getSecretKey();
            break;

        case WSConstants.THUMBPRINT_IDENTIFIER:
            secRef.setKeyIdentifierThumb(certs[0]);
            break;

        default:
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "unsupportedKeyId");
        }
        if (tlog.isDebugEnabled()) {
            t3 = System.currentTimeMillis();
        }
        info.addUnknownElement(secRef.getElement());

        WSDocInfoStore.store(wsDocInfo);
        try {
            if (keyIdentifierType == WSConstants.UT_SIGNING) {
                sig.sign(sig.createSecretKey(secretKey));
            } else {
                sig.sign(crypto.getPrivateKey(user, password));
            }
            signatureValue = sig.getSignatureValue();
        } catch (XMLSignatureException e1) {
            throw new WSSecurityException(WSSecurityException.FAILED_SIGNATURE,
                    null, null, e1);
        } catch (Exception e1) {
            throw new WSSecurityException(WSSecurityException.FAILED_SIGNATURE,
                    null, null, e1);
        } finally {
            WSDocInfoStore.delete(wsDocInfo);
        }
        if (tlog.isDebugEnabled()) {
            t4 = System.currentTimeMillis();
            tlog.debug("SignEnvelope: cre-Sig= " + (t1 - t0)
                    + " set transform= " + (t2 - t1) + " sec-ref= " + (t3 - t2)
                    + " signature= " + (t4 - t3));
        }
        if (doDebug) {
            log.debug("Signing complete.");
        }
        return (doc);
    }

    /**
     * Builds a signed soap envelope with SAML token. <p/>The method first
     * gets an appropriate security header. According to the defined parameters
     * for certificate handling the signature elements are constructed and
     * inserted into the <code>wsse:Signature</code>
     *
     * @param doc           The unsigned SOAP envelope as <code>Document</code>
     * @param assertion     the complete SAML assertion
     * @param issuerCrypto  An instance of the Crypto API to handle keystore SAML token
     *                      issuer and to generate certificates
     * @param issuerKeyName Private key to use in case of "sender-Vouches"
     * @param issuerKeyPW   Password for issuer private key
     * @return A signed SOAP envelope as <code>Document</code>
     * @throws WSSecurityException
     */
    public Document build(Document doc, Crypto userCrypto,
            SAMLAssertion assertion, Crypto issuerCrypto, String issuerKeyName,
            String issuerKeyPW) throws WSSecurityException {

        doDebug = log.isDebugEnabled();

        long t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0;
        if (tlog.isDebugEnabled()) {
            t0 = System.currentTimeMillis();
        }
        if (doDebug) {
            log.debug("Beginning ST signing...");
        }
        /*
         * Get some information about the SAML token content. This controls how
         * to deal with the whole stuff. First get the Authentication statement
         * (includes Subject), then get the _first_ confirmation method only.
         */
        SAMLSubjectStatement samlSubjS = null;
        Iterator it = assertion.getStatements();
        while (it.hasNext()) {
            SAMLObject so = (SAMLObject) it.next();
            if (so instanceof SAMLSubjectStatement) {
                samlSubjS = (SAMLSubjectStatement) so;
                break;
            }
        }
        SAMLSubject samlSubj = null;
        if (samlSubjS != null) {
            samlSubj = samlSubjS.getSubject();
        }
        if (samlSubj == null) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "invalidSAMLToken", new Object[] { "for Signature" });
        }

        String confirmMethod = null;
        it = samlSubj.getConfirmationMethods();
        if (it.hasNext()) {
            confirmMethod = (String) it.next();
        }
        boolean senderVouches = false;
        if (SAMLSubject.CONF_SENDER_VOUCHES.equals(confirmMethod)) {
            senderVouches = true;
        }
        /*
         * Gather some info about the document to process and store it for
         * retrival
         */
        WSDocInfo wsDocInfo = new WSDocInfo(doc.hashCode());

        Element envelope = doc.getDocumentElement();
        SOAPConstants soapConstants = WSSecurityUtil.getSOAPConstants(envelope);

        Element securityHeader = insertSecurityHeader(doc);
        X509Certificate[] certs = null;

        if (senderVouches) {
            certs = issuerCrypto.getCertificates(issuerKeyName);
            wsDocInfo.setCrypto(issuerCrypto);
        }
        /*
         * in case of key holder:
         * - get the user's certificate that _must_ be included in the SAML
         * token. To ensure the cert integrity the SAML token must be signed
         * (by the issuer). Just check if its signed, but
         * don't verify this SAML token's signature here (maybe later).
         */
        else {
            if (userCrypto == null || assertion.isSigned() == false) {
                throw new WSSecurityException(WSSecurityException.FAILURE,
                        "invalidSAMLsecurity",
                        new Object[] { "for SAML Signature (Key Holder)" });
            }
            Element e = samlSubj.getKeyInfo();
            try {
                KeyInfo ki = new KeyInfo(e, null);

                if (ki.containsX509Data()) {
                    X509Data data = ki.itemX509Data(0);
                    XMLX509Certificate certElem = null;
                    if (data != null && data.containsCertificate()) {
                        certElem = data.itemCertificate(0);
                    }
                    if (certElem != null) {
                        X509Certificate cert = certElem.getX509Certificate();
                        certs = new X509Certificate[1];
                        certs[0] = cert;
                    }
                }
                // TODO: get alias name for cert, check against username set by caller
            } catch (XMLSecurityException e3) {
                throw new WSSecurityException(WSSecurityException.FAILURE,
                        "invalidSAMLsecurity",
                        new Object[] { "cannot get certificate (key holder)" },
                        e3);
            }
            wsDocInfo.setCrypto(userCrypto);
        }
        // Set the id of the elements to be used as digest source
        // String id = setBodyID(doc);
        if (certs == null || certs.length <= 0) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "invalidX509Data", new Object[] { "for Signature" });
        }
        if (sigAlgo == null) {
            String pubKeyAlgo = certs[0].getPublicKey().getAlgorithm();
            log.debug("automatic sig algo detection: " + pubKeyAlgo);
            if (pubKeyAlgo.equalsIgnoreCase("DSA")) {
                sigAlgo = XMLSignature.ALGO_ID_SIGNATURE_DSA;
            } else if (pubKeyAlgo.equalsIgnoreCase("RSA")) {
                sigAlgo = XMLSignature.ALGO_ID_SIGNATURE_RSA;
            } else {
                throw new WSSecurityException(
                        WSSecurityException.FAILURE,
                        "invalidX509Data",
                        new Object[] { "for Signature - unkown public key Algo" });
            }
        }
        XMLSignature sig = null;
        try {
            sig = new XMLSignature(doc, null, sigAlgo, canonAlgo);
        } catch (XMLSecurityException e) {
            throw new WSSecurityException(WSSecurityException.FAILED_SIGNATURE,
                    "noXMLSig");
        }

        KeyInfo info = sig.getKeyInfo();
        String keyInfoUri = "KeyId-" + info.hashCode();
        info.setId(keyInfoUri);

        SecurityTokenReference secRef = new SecurityTokenReference(doc);
        String strUri = "STRId-" + secRef.hashCode();
        secRef.setID(strUri);

        String certUri = "CertId-" + certs[0].hashCode();

        if (tlog.isDebugEnabled()) {
            t1 = System.currentTimeMillis();
        }

        if (parts == null) {
            parts = new Vector();
            WSEncryptionPart encP = new WSEncryptionPart(soapConstants
                    .getBodyQName().getLocalPart(), soapConstants
                    .getEnvelopeURI(), "Content");
            parts.add(encP);
        }

        /*
         * If the sender vouches, then we must sign the SAML token _and_ at
         * least one part of the message (usually the SOAP body). To do so we
         * need to
         * - put in a reference to the SAML token. Thus we create a STR
         *   and insert it into the wsse:Security header
         * - set a reference of the created STR to the signature and use STR
         *   Transfrom during the signature
         */
        Transforms transforms = null;
        SecurityTokenReference secRefSaml = null;

        try {
            if (senderVouches) {
                secRefSaml = new SecurityTokenReference(doc);
                String strSamlUri = "STRSAMLId-" + secRefSaml.hashCode();
                secRefSaml.setID(strSamlUri);
                // Decouple Refernce/KeyInfo setup - quick shot here
                Reference ref = new Reference(doc);
                ref.setURI("#" + assertion.getId());
                ref.setValueType(WSConstants.WSS_SAML_NS
                        + WSConstants.WSS_SAML_ASSERTION);
                secRefSaml.setReference(ref);
                // up to here
                Element ctx = createSTRParameter(doc);
                transforms = new Transforms(doc);
                transforms.addTransform(STRTransform.implementedTransformURI,
                        ctx);
                sig.addDocument("#" + strSamlUri, transforms);
            }
            for (int part = 0; part < parts.size(); part++) {
                WSEncryptionPart encPart = (WSEncryptionPart) parts.get(part);
                String elemName = encPart.getName();
                String nmSpace = encPart.getNamespace();

                /*
                 * Set up the elements to sign. There are two resevered element
                 * names: "Token" and "STRTransform" "Token": Setup the
                 * Signature to either sign the information that points to the
                 * security token or the token itself. If its a direct
                 * reference sign the token, otherwise sign the KeyInfo
                 * Element. "STRTransform": Setup the ds:Reference to use STR
                 * Transform
                 *
                 */
                if (elemName.equals("Token")) {
                    transforms = new Transforms(doc);
                    transforms
                            .addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
                    if (keyIdentifierType == WSConstants.BST_DIRECT_REFERENCE) {
                        sig.addDocument("#" + certUri, transforms);
                    } else {
                        sig.addDocument("#" + keyInfoUri, transforms);
                    }
                } else if (elemName.equals("STRTransform")) { // STRTransform
                    Element ctx = createSTRParameter(doc);
                    transforms = new Transforms(doc);
                    transforms.addTransform(
                            STRTransform.implementedTransformURI, ctx);
                    sig.addDocument("#" + strUri, transforms);
                } else {
                    Element body = (Element) WSSecurityUtil.findElement(
                            envelope, elemName, nmSpace);
                    if (body == null) {
                        throw new WSSecurityException(
                                WSSecurityException.FAILURE, "noEncElement",
                                new Object[] { nmSpace + ", " + elemName });
                    }
                    transforms = new Transforms(doc);
                    transforms
                            .addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
                    sig.addDocument("#" + setWsuId(body), transforms);
                }
            }
        } catch (TransformationException e1) {
            throw new WSSecurityException(WSSecurityException.FAILED_SIGNATURE,
                    "noXMLSig", null, e1);
        } catch (XMLSignatureException e1) {
            throw new WSSecurityException(WSSecurityException.FAILED_SIGNATURE,
                    "noXMLSig", null, e1);
        }

        sig.addResourceResolver(EnvelopeIdResolver.getInstance());

        /*
         * The order to prepend is:
         * - signature
         * - BinarySecurityToken (depends on mode)
         * - SecurityTokenRefrence (depends on mode)
         * - SAML token
         */

        WSSecurityUtil.prependChildElement(doc, securityHeader, sig
                .getElement(), false);

        if (tlog.isDebugEnabled()) {
            t2 = System.currentTimeMillis();
        }
        switch (keyIdentifierType) {
        case WSConstants.BST_DIRECT_REFERENCE:
            Reference ref = new Reference(doc);
            if (senderVouches) {
                ref.setURI("#" + certUri);
                BinarySecurity bstToken = null;
                bstToken = new X509Security(doc);
                ((X509Security) bstToken).setX509Certificate(certs[0]);
                bstToken.setID(certUri);
                WSSecurityUtil.prependChildElement(doc, securityHeader,
                        bstToken.getElement(), false);
                wsDocInfo.setBst(bstToken.getElement());
                ref.setValueType(bstToken.getValueType());
            } else {
                ref.setURI("#" + assertion.getId());
                ref.setValueType(WSConstants.WSS_SAML_NS
                        + WSConstants.WSS_SAML_ASSERTION);
            }
            secRef.setReference(ref);
            break;
        //
        //            case WSConstants.ISSUER_SERIAL :
        //                XMLX509IssuerSerial data =
        //                    new XMLX509IssuerSerial(doc, certs[0]);
        //                secRef.setX509IssuerSerial(data);
        //                break;
        //
        //            case WSConstants.X509_KEY_IDENTIFIER :
        //                secRef.setKeyIdentifier(certs[0]);
        //                break;
        //
        //            case WSConstants.SKI_KEY_IDENTIFIER :
        //                secRef.setKeyIdentifierSKI(certs[0], crypto);
        //                break;
        //
        default:
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "unsupportedKeyId");
        }

        if (tlog.isDebugEnabled()) {
            t3 = System.currentTimeMillis();
        }
        info.addUnknownElement(secRef.getElement());

        Element samlToken = null;
        try {
            samlToken = (Element) assertion.toDOM(doc);
        } catch (SAMLException e2) {
            throw new WSSecurityException(WSSecurityException.FAILED_SIGNATURE,
                    "noSAMLdoc", null, e2);
        }
        if (senderVouches) {
            WSSecurityUtil.prependChildElement(doc, securityHeader, secRefSaml
                    .getElement(), true);
        }

        wsDocInfo.setAssertion(samlToken);
        WSSecurityUtil
                .prependChildElement(doc, securityHeader, samlToken, true);

        WSDocInfoStore.store(wsDocInfo);
        try {
            if (senderVouches) {
                sig
                        .sign(issuerCrypto.getPrivateKey(issuerKeyName,
                                issuerKeyPW));
            } else {
                sig.sign(userCrypto.getPrivateKey(user, password));
            }
            signatureValue = sig.getSignatureValue();            
        } catch (XMLSignatureException e1) {
            throw new WSSecurityException(WSSecurityException.FAILED_SIGNATURE,
                    null, null, e1);
        } catch (Exception e1) {
            throw new WSSecurityException(WSSecurityException.FAILED_SIGNATURE,
                    null, null, e1);
        } finally {
            WSDocInfoStore.delete(wsDocInfo);
        }
        if (tlog.isDebugEnabled()) {
            t4 = System.currentTimeMillis();
            tlog.debug("SignEnvelope: cre-Sig= " + (t1 - t0)
                    + " set transform= " + (t2 - t1) + " sec-ref= " + (t3 - t2)
                    + " signature= " + (t4 - t3));
        }
        if (doDebug) {
            log.debug("Signing complete.");
        }
        return (doc);

    }

    private Element createSTRParameter(Document doc) {
        Element transformParam = doc.createElementNS(WSConstants.WSSE_NS,
                WSConstants.WSSE_PREFIX + ":TransformationParameters");

        WSSecurityUtil.setNamespace(transformParam, WSConstants.WSSE_NS,
                WSConstants.WSSE_PREFIX);

        Element canonElem = doc.createElementNS(WSConstants.SIG_NS,
                WSConstants.SIG_PREFIX + ":CanonicalizationMethod");

        WSSecurityUtil.setNamespace(canonElem, WSConstants.SIG_NS,
                WSConstants.SIG_PREFIX);

        canonElem.setAttributeNS(null, "Algorithm",
                Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        transformParam.appendChild(canonElem);
        return transformParam;
    }

    protected Set getInclusivePrefixes(Element target) {
        return getInclusivePrefixes(target, true);
    }

    protected Set getInclusivePrefixes(Element target, boolean excludeVisible) {
        Set result = new HashSet();
        Node parent = target;
        NamedNodeMap attributes;
        Node attribute;
        while (!(parent.getParentNode() instanceof Document)) {
            parent = parent.getParentNode();
            attributes = parent.getAttributes();
            for (int i = 0; i < attributes.getLength(); i++) {
                attribute = attributes.item(i);
                if (attribute.getNamespaceURI() != null
                        && attribute.getNamespaceURI().equals(
                                org.apache.ws.security.WSConstants.XMLNS_NS)) {
                    if (attribute.getNodeName().equals("xmlns")) {
                        result.add("#default");
                    } else {
                        result.add(attribute.getLocalName());
                    }
                }
            }
        }

        if (excludeVisible == true) {
            attributes = target.getAttributes();
            for (int i = 0; i < attributes.getLength(); i++) {
                attribute = attributes.item(i);
                if (attribute.getNamespaceURI() != null
                        && attribute.getNamespaceURI().equals(
                                org.apache.ws.security.WSConstants.XMLNS_NS)) {
                    if (attribute.getNodeName().equals("xmlns")) {
                        result.remove("#default");
                    } else {
                        result.remove(attribute.getLocalName());
                    }
                }
                if (attribute.getPrefix() != null) {
                    result.remove(attribute.getPrefix());
                }
            }

            if (target.getPrefix() == null) {
                result.remove("#default");
            } else {
                result.remove(target.getPrefix());
            }
        }

        return result;
    }
}
