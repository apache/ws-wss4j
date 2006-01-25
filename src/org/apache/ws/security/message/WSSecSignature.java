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
import org.apache.ws.security.saml.SAMLUtil;
import org.apache.ws.security.transform.STRTransform;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.algorithms.SignatureAlgorithm;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.keys.content.x509.XMLX509IssuerSerial;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.transforms.TransformationException;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.transforms.params.InclusiveNamespaces;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;
import java.util.Vector;

/**
 * Creates a Signature according to WS Specification, X509 profile.
 * 
 * This class is a refactored implementation of the previous WSS4J class
 * <code>WSSigneEnvlope</code>. This new class allows the better control of
 * the process to create a Signature and to add it to the Security header.
 * 
 * <br/>
 * 
 * The flexibility and fine granular control is required to implement a handler
 * that uses WSSecurityPolicy files to control the setup of a Security header.
 * 
 * @author Davanum Srinivas (dims@yahoo.com)
 * @author Werner Dittmann (werner@apache.org)
 */
public class WSSecSignature extends WSSecBase {

    private static Log log = LogFactory.getLog(WSSecSignature.class.getName());

    protected boolean useSingleCert = true;

    protected String sigAlgo = null;

    protected String canonAlgo = Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS;

    protected WSSAddUsernameToken usernameToken = null;

    protected byte[] signatureValue = null;

    /*
     * The following private variable are setup during setupToken().
     */
    private Document document = null;

    private Crypto crypto = null;

    private WSDocInfo wsDocInfo = null;

    private String certUri = null;

    private XMLSignature sig = null;

    private KeyInfo keyInfo = null;

    private String keyInfoUri = null;

    private SecurityTokenReference secRef = null;

    private String strUri = null;

    private byte[] secretKey = null;

    private BinarySecurity bstToken = null;

    /**
     * Constructor.
     */
    public WSSecSignature() {
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
     * @return A blolean if single vertificate is set.
     */
    public boolean isUseSingleCertificate() {
        return this.useSingleCert;
    }

    /**
     * Set the name of the signature encryption algorithm to use.
     * 
     * If the algorithm is not set then an automatic detection of the signature
     * algorithm to use is perfomed during the <code>setupToken()</code>
     * method. Refer to WSConstants which algorithms are supported.
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
     * Call this method after <code>setupToken</code> to get the information
     * which signature algorithem was automaticall detected if no signature
     * algorithm was preset.
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
     * @return The string describing the canonicalization algorithm.
     */
    public String getSigCanonicalization() {
        return canonAlgo;
    }

    /**
     * @param usernameToken
     *            The usernameToken to set.
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
     * Initialize a WSSec Signature.
     * 
     * The method sets up and initializes a WSSec Signature structure after the
     * relevant token information was set. After setup of the token references
     * may be added. After all references are added they can be signed.
     * 
     * 
     * @param doc
     *            The unsigned SOAP envelope as <code>Document</code>
     * @param cr
     *            An instance of the Crypto API to handle keystore and
     *            certificates
     * @throws WSSecurityException
     */
    public void setupToken(Document doc, Crypto cr, Element securityHeader)
            throws WSSecurityException {
        /*
         * Gather some info about the document to process and store it for
         * retrival
         */
        crypto = cr;
        document = doc;

        wsDocInfo = new WSDocInfo(doc.hashCode());
        wsDocInfo.setCrypto(cr);

        /*
         * At first get the security token (certificate) according to the
         * parameters.
         */
        X509Certificate[] certs = null;
        if (keyIdentifierType != WSConstants.UT_SIGNING) {
            certs = crypto.getCertificates(user);
            if (certs == null || certs.length <= 0) {
                throw new WSSecurityException(WSSecurityException.FAILURE,
                        "invalidX509Data", new Object[] { "for Signature" });
            }
            certUri = "CertId-" + certs[0].hashCode();
            /*
             * If no signature algo was set try to detect it accroding to the
             * data stored in the certificate.
             */
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

        /*
         * Get an initialize a XMLSignature element.
         */
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

        sig.addResourceResolver(EnvelopeIdResolver.getInstance());

        keyInfo = sig.getKeyInfo();
        keyInfoUri = "KeyId-" + keyInfo.hashCode();
        keyInfo.setId(keyInfoUri);

        secRef = new SecurityTokenReference(doc);
        strUri = "STRId-" + secRef.hashCode();
        secRef.setID(strUri);

        /*
         * Prepare and setup the token references for this Signature
         */
        switch (keyIdentifierType) {
        case WSConstants.BST_DIRECT_REFERENCE:
            Reference ref = new Reference(document);
            ref.setURI("#" + certUri);
            if (!useSingleCert) {
                bstToken = new PKIPathSecurity(document);
                ((PKIPathSecurity) bstToken).setX509Certificates(certs, false,
                        crypto);
            } else {
                bstToken = new X509Security(document);
                ((X509Security) bstToken).setX509Certificate(certs[0]);
            }
            ref.setValueType(bstToken.getValueType());
            secRef.setReference(ref);
            bstToken.setID(certUri);
            wsDocInfo.setBst(bstToken.getElement());
            break;

        case WSConstants.ISSUER_SERIAL:
            XMLX509IssuerSerial data = new XMLX509IssuerSerial(document,
                    certs[0]);
            X509Data x509Data = new X509Data(document);
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
            Reference refUt = new Reference(document);
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
        keyInfo.addUnknownElement(secRef.getElement());

    }

    /**
     * This method adds references to the Signature.
     * 
     * The added references are signed when calling
     * <code>computeSignature()</code>. This method can be called several
     * times to add references as required. <code>addReferencesToSign()</code>
     * can be called anytime after <code>setupToken</code>.
     * 
     * @param references
     *            A vector containing <code>WSEncryptionPart</code> objects
     *            that define the parts to sign.
     * @param securityHeader
     *            Used to compute namespaces to be inserted by
     *            InclusiveNamespaces to be WSI compliant.
     * @throws WSSecurityException
     */
    public void addReferencesToSign(Vector references, Element securityHeader)
            throws WSSecurityException {
        Transforms transforms = null;

        Element envelope = document.getDocumentElement();

        for (int part = 0; part < references.size(); part++) {
            WSEncryptionPart encPart = (WSEncryptionPart) references.get(part);

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
            transforms = new Transforms(document);
            try {
                if (idToSign != null) {
                    Element toSignById = WSSecurityUtil.findElementById(
                            document.getDocumentElement(), idToSign,
                            WSConstants.WSU_NS);
                    if (toSignById == null) {
                        toSignById = WSSecurityUtil.findElementById(document
                                .getDocumentElement(), idToSign, null);
                    }
                    transforms
                            .addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
                    if (wssConfig.isWsiBSPCompliant()) {
                        transforms.item(0).getElement().appendChild(
                                new InclusiveNamespaces(document,
                                        getInclusivePrefixes(toSignById))
                                        .getElement());
                    }
                    sig.addDocument("#" + idToSign, transforms);
                } else if (elemName.equals("Token")) {
                    transforms
                            .addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
                    if (keyIdentifierType == WSConstants.BST_DIRECT_REFERENCE) {
                        if (wssConfig.isWsiBSPCompliant()) {
                            transforms
                                    .item(0)
                                    .getElement()
                                    .appendChild(
                                            new InclusiveNamespaces(
                                                    document,
                                                    getInclusivePrefixes(securityHeader))
                                                    .getElement());
                        }
                        sig.addDocument("#" + certUri, transforms);
                    } else {
                        if (wssConfig.isWsiBSPCompliant()) {
                            transforms.item(0).getElement().appendChild(
                                    new InclusiveNamespaces(document,
                                            getInclusivePrefixes(keyInfo
                                                    .getElement()))
                                            .getElement());
                        }
                        sig.addDocument("#" + keyInfoUri, transforms);
                    }
                } else if (elemName.equals("STRTransform")) { // STRTransform
                    Element ctx = createSTRParameter(document);
                    transforms.addTransform(
                            STRTransform.implementedTransformURI, ctx);
                    sig.addDocument("#" + strUri, transforms);
                } else if (elemName.equals("Assertion")) { // Assertion

                    String id = null;
                    id = SAMLUtil.getAssertionId(envelope, elemName, nmSpace);

                    Element body = (Element) WSSecurityUtil.findElement(
                            envelope, elemName, nmSpace);
                    if (body == null) {
                        throw new WSSecurityException(
                                WSSecurityException.FAILURE, "noEncElement",
                                new Object[] { nmSpace + ", " + elemName });
                    }
                    transforms
                            .addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
                    if (wssConfig.isWsiBSPCompliant()) {
                        transforms.item(0).getElement().appendChild(
                                new InclusiveNamespaces(document,
                                        getInclusivePrefixes(body))
                                        .getElement());
                    }
                    String prefix = WSSecurityUtil.setNamespace(body,
                            WSConstants.WSU_NS, WSConstants.WSU_PREFIX);
                    body.setAttributeNS(WSConstants.WSU_NS, prefix + ":Id", id);
                    sig.addDocument("#" + id, transforms);

                } else {
                    Element body = (Element) WSSecurityUtil.findElement(
                            envelope, elemName, nmSpace);
                    if (body == null) {
                        throw new WSSecurityException(
                                WSSecurityException.FAILURE, "noEncElement",
                                new Object[] { nmSpace + ", " + elemName });
                    }
                    transforms
                            .addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
                    if (wssConfig.isWsiBSPCompliant()) {
                        transforms.item(0).getElement().appendChild(
                                new InclusiveNamespaces(document,
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
    }

    /**
     * Prepends the Signature element to the elements already in the Security
     * header.
     * 
     * The method can be called any time after <code>setupToken()</code>.
     * This allows to insert the Signature element at any position in the
     * Security header.
     * 
     * @param securityHeader
     *            The securityHeader that holds the Signature element.
     */
    public void prependSignatureElementToHeader(Element securityHeader) {
        WSSecurityUtil.prependChildElement(document, securityHeader, sig
                .getElement(), false);
    }

    /**
     * Prepend the BinarySecurityToken to the elements already in the Security
     * header.
     * 
     * The method can be called any time after <code>setupToken()</code>.
     * This allows to insert the BST element at any position in the Security
     * header.
     * 
     * @param securityHeader
     *            The securityHeader that holds the BST element.
     */
    public void prependBSTElementToHeader(Element securityHeader) {
        if (bstToken != null) {
            WSSecurityUtil.prependChildElement(document, securityHeader,
                    bstToken.getElement(), false);
        }

    }

    /**
     * Compute the Signature over the references.
     * 
     * After references are set this method computes the Signature for them.
     * This method can be called anytime after the references are set using
     * <code>addReferencesToSign()</code>.
     * 
     * @throws WSSecurityException
     */
    public void computeSignature() throws WSSecurityException {
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

    }

    /**
     * Builds a signed soap envelope.
     * 
     * This is a convenience method and for backward compatibility. The method
     * creates a Signature and puts it into the Security header. It does so by
     * calling functions in order. This build() method produces a Signature that
     * is equivalent to the WSSignEnvelope.build().
     * 
     * @param doc
     *            The unsigned SOAP envelope as <code>Document</code>
     * @param crypto
     *            An instance of the Crypto API to handle keystore and
     *            certificates
     * @return A signed SOAP envelope as <code>Document</code>
     * @throws WSSecurityException
     */
    public Document build(Document doc, Crypto cr, WSSecHeader secHeader) throws WSSecurityException {
        doDebug = log.isDebugEnabled();

        if (doDebug) {
            log.debug("Beginning signing...");
        }

        Element securityHeader = secHeader.getSecurityHeader();

        setupToken(doc, cr, securityHeader);

        SOAPConstants soapConstants = WSSecurityUtil.getSOAPConstants(doc
                .getDocumentElement());

        if (parts == null) {
            parts = new Vector();
            WSEncryptionPart encP = new WSEncryptionPart(soapConstants
                    .getBodyQName().getLocalPart(), soapConstants
                    .getEnvelopeURI(), "Content");
            parts.add(encP);
        }

        addReferencesToSign(parts, securityHeader);

        prependSignatureElementToHeader(securityHeader);

        /*
         * if we have a BST prepend it in front of the Signature according to
         * strict layout rules.
         */
        if (bstToken != null) {
            prependBSTElementToHeader(securityHeader);
        }

        computeSignature();

        return (doc);
    }

    protected Element createSTRParameter(Document doc) {
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
