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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSDocInfoStore;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.message.token.BinarySecurity;
import org.apache.ws.security.message.token.PKIPathSecurity;
import org.apache.ws.security.message.token.Reference;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.message.token.X509Security;
import org.apache.ws.security.transform.STRTransform;
import org.apache.ws.security.util.Base64;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.algorithms.SignatureAlgorithm;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.keys.content.x509.XMLX509IssuerSerial;
import org.apache.xml.security.keys.content.keyvalues.DSAKeyValue;
import org.apache.xml.security.keys.content.keyvalues.RSAKeyValue;
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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Vector;

/**
 * Creates a Signature according to WS Specification, X509 profile.
 * 
 * This class is a re-factored implementation of the previous WSS4J class
 * <code>WSSignEnvelope</code>. This new class allows better control of
 * the process to create a Signature and to add it to the Security header.
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
    protected String canonAlgo = WSConstants.C14N_EXCL_OMIT_COMMENTS;
    protected byte[] signatureValue = null;
    protected Document document = null;
    protected WSDocInfo wsDocInfo = null;
    protected String certUri = null;
    protected XMLSignature sig = null;
    protected KeyInfo keyInfo = null;
    protected String keyInfoUri = null;
    protected SecurityTokenReference secRef = null;
    protected String strUri = null;
    protected BinarySecurity bstToken = null;

    private byte[] secretKey = null;
    private String encrKeySha1value = null;
    private Crypto crypto = null;
    private String customTokenValueType;
    private String customTokenId;
    private String digestAlgo = "http://www.w3.org/2000/09/xmldsig#sha1";
    private X509Certificate useThisCert = null;

   
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
     * @param doc The SOAP envelope as <code>Document</code>
     * @param cr An instance of the Crypto API to handle keystore and certificates
     * @param secHeader The security header that will hold the Signature. This is used
     *                   to construct namespace prefixes for Signature. This method
     * @throws WSSecurityException
     */
    public void prepare(Document doc, Crypto cr, WSSecHeader secHeader)
        throws WSSecurityException {
        //
        // Gather some info about the document to process and store it for
        // retrieval
        //
        crypto = cr;
        document = doc;
        wsDocInfo = new WSDocInfo(doc);
        wsDocInfo.setCrypto(cr);

        //
        // At first get the security token (certificate) according to the parameters.
        //
        X509Certificate[] certs = getSigningCerts();

        //
        // Get an initialized XMLSignature element.
        //
        if (wssConfig.isWsiBSPCompliant() && canonAlgo.equals(WSConstants.C14N_EXCL_OMIT_COMMENTS)) {
            sig = 
                createXMLSignatureInclusivePrefixes(
                    doc, secHeader.getSecurityHeader(), canonAlgo, sigAlgo
                );
        } else {
            try {
                sig = new XMLSignature(doc, null, sigAlgo, canonAlgo);
            } catch (XMLSecurityException e) {
                log.error("", e);
                throw new WSSecurityException(
                    WSSecurityException.FAILED_SIGNATURE, "noXMLSig", null, e
                );
            }
        }

        sig.addResourceResolver(EnvelopeIdResolver.getInstance());
        sig.setId(wssConfig.getIdAllocator().createId("Sig-", sig));

        keyInfo = sig.getKeyInfo();
        keyInfoUri = wssConfig.getIdAllocator().createSecureId("KI-", keyInfo);
        keyInfo.setId(keyInfoUri);

        secRef = new SecurityTokenReference(doc);
        strUri = wssConfig.getIdAllocator().createSecureId("STR-", secRef);
        secRef.setID(strUri);
        
        //
        // Prepare and setup the token references for this Signature
        //
        switch (keyIdentifierType) {
        case WSConstants.BST_DIRECT_REFERENCE:
            Reference ref = new Reference(document);
            ref.setURI("#" + certUri);
            if (!useSingleCert) {
                bstToken = new PKIPathSecurity(document);
                ((PKIPathSecurity) bstToken).setX509Certificates(certs, false, crypto);
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
            XMLX509IssuerSerial data = new XMLX509IssuerSerial(document, certs[0]);
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

        case WSConstants.THUMBPRINT_IDENTIFIER:
            secRef.setKeyIdentifierThumb(certs[0]);
            break;
            
        case WSConstants.ENCRYPTED_KEY_SHA1_IDENTIFIER:
            if (encrKeySha1value != null) {
                secRef.setKeyIdentifierEncKeySHA1(encrKeySha1value);
            } else {
                secRef.setKeyIdentifierEncKeySHA1(getSHA1(secretKey));
            }
            break;

        case WSConstants.CUSTOM_SYMM_SIGNING :
            Reference refCust = new Reference(document);
            refCust.setValueType(customTokenValueType);
            refCust.setURI("#" + customTokenId);
            secRef.setReference(refCust);
            break;

        case WSConstants.CUSTOM_SYMM_SIGNING_DIRECT :
            Reference refCustd = new Reference(document);
            refCustd.setValueType(customTokenValueType);
            refCustd.setURI(customTokenId);
            secRef.setReference(refCustd);
            break;
            
        case WSConstants.CUSTOM_KEY_IDENTIFIER:
            secRef.setKeyIdentifier(customTokenValueType, customTokenId);
            break;
            
        case WSConstants.KEY_VALUE:
            java.security.PublicKey publicKey = certs[0].getPublicKey();
            String pubKeyAlgo = publicKey.getAlgorithm();
            if (pubKeyAlgo.equalsIgnoreCase("DSA")) {
                DSAKeyValue dsaKeyValue = new DSAKeyValue(document, publicKey);
                keyInfo.add(dsaKeyValue);
            } else if (pubKeyAlgo.equalsIgnoreCase("RSA")) {
                RSAKeyValue rsaKeyValue = new RSAKeyValue(document, publicKey);
                keyInfo.add(rsaKeyValue);
            } else {
                throw new WSSecurityException(
                    WSSecurityException.FAILURE,
                    "unknownSignatureAlgorithm",
                    new Object[] {pubKeyAlgo}
                );
            }
            break;
        default:
            throw new WSSecurityException(WSSecurityException.FAILURE, "unsupportedKeyId");
        }
        if (keyIdentifierType != WSConstants.KEY_VALUE) {
            keyInfo.addUnknownElement(secRef.getElement());
        }
    }
    
    
    /**
     * Builds a signed soap envelope.
     * 
     * This is a convenience method and for backward compatibility. The method
     * creates a Signature and puts it into the Security header. It does so by
     * calling the single functions in order to perform a <i>one shot signature</i>.
     * This method is compatible with the build method of the previous version
     * with the exception of the additional WSSecHeader parameter.
     * 
     * @param doc The unsigned SOAP envelope as <code>Document</code>
     * @param cr An instance of the Crypto API to handle keystore and certificates
     * @param secHeader the security header element to hold the encrypted key element.
     * @return A signed SOAP envelope as <code>Document</code>
     * @throws WSSecurityException
     */
    public Document build(Document doc, Crypto cr, WSSecHeader secHeader)
        throws WSSecurityException {
        doDebug = log.isDebugEnabled();

        if (doDebug) {
            log.debug("Beginning signing...");
        }

        prepare(doc, cr, secHeader);
        if (parts == null) {
            parts = new Vector();
            String soapNamespace = WSSecurityUtil.getSOAPNamespace(doc.getDocumentElement());
            WSEncryptionPart encP = 
                new WSEncryptionPart(
                    WSConstants.ELEM_BODY, 
                    soapNamespace, 
                    "Content"
                );
            parts.add(encP);
        }

        addReferencesToSign(parts, secHeader);
        prependToHeader(secHeader);

        //
        // if we have a BST prepend it in front of the Signature according to
        // strict layout rules.
        //
        if (bstToken != null) {
            prependBSTElementToHeader(secHeader);
        }

        computeSignature();

        return doc;
    }
    
    
    /**
     * This method adds references to the Signature.
     * 
     * @param references The list of references to sign
     * @param secHeader The Security Header
     * @throws WSSecurityException
     */
    public void addReferencesToSign(List references, WSSecHeader secHeader) throws WSSecurityException {
        addReferencesToSign(document, references, sig, secHeader, wssConfig, digestAlgo, strUri);
    }

    
    /**
     * This method adds references to the Signature.
     * 
     * @param doc The parent document
     * @param references The list of references to sign
     * @param sig The XMLSignature object
     * @param secHeader The Security Header
     * @param wssConfig The WSSConfig
     * @param digestAlgo The digest algorithm to use
     * @param strUri The SecurityTokenReference uri to use for STRTransform
     * @throws WSSecurityException
     */
    public static void addReferencesToSign(
        Document doc,
        List references,
        XMLSignature sig,
        WSSecHeader secHeader,
        WSSConfig wssConfig,
        String digestAlgo,
        String strUri
    ) throws WSSecurityException {
        Element envelope = doc.getDocumentElement();

        for (int part = 0; part < references.size(); part++) {
            WSEncryptionPart encPart = (WSEncryptionPart) references.get(part);

            String idToSign = encPart.getId();
            String elemName = encPart.getName();

            //
            // Set up the elements to sign. There is one reserved element
            // names: "STRTransform": Setup the ds:Reference to use STR Transform
            //
            Transforms transforms = new Transforms(doc);
            try {
                if (idToSign != null) {
                    Element toSignById = 
                        WSSecurityUtil.findElementById(
                            envelope, idToSign, WSConstants.WSU_NS
                        );
                    if (toSignById == null) {
                        toSignById = 
                            WSSecurityUtil.findElementById(
                                envelope, idToSign, null
                            );
                    }
                    transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
                    if (wssConfig.isWsiBSPCompliant()) {
                        transforms.item(0).getElement().appendChild(
                            new InclusiveNamespaces(
                                doc, getInclusivePrefixes(toSignById)).getElement()
                            );
                    }
                    sig.addDocument("#" + idToSign, transforms, digestAlgo);
                } else if (elemName.equals("STRTransform")) {
                    Element ctx = createSTRParameter(doc);
                    transforms.addTransform(STRTransform.TRANSFORM_URI, ctx);
                    sig.addDocument("#" + strUri, transforms, digestAlgo);
                } else {
                    String nmSpace = encPart.getNamespace();
                    Element elementToSign = 
                        (Element)WSSecurityUtil.findElement(envelope, elemName, nmSpace);
                    if (elementToSign == null) {
                        throw new WSSecurityException(
                            WSSecurityException.FAILURE, 
                            "noEncElement",
                            new Object[] {nmSpace + ", " + elemName}
                        );
                    }
                    transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
                    if (wssConfig.isWsiBSPCompliant()) {
                        transforms.item(0).getElement().appendChild(
                            new InclusiveNamespaces(
                                doc, getInclusivePrefixes(elementToSign)).getElement()
                            );
                    }
                    sig.addDocument("#" + setWsuId(elementToSign, wssConfig), transforms, digestAlgo);
                }
            } catch (TransformationException ex) {
                throw new WSSecurityException(
                    WSSecurityException.FAILED_SIGNATURE, "noXMLSig", null, ex
                );
            } catch (XMLSignatureException ex) {
                throw new WSSecurityException(
                    WSSecurityException.FAILED_SIGNATURE, "noXMLSig", null, ex
                );
            }
        }
    }

    /**
     * Prepends the Signature element to the elements already in the Security
     * header.
     * 
     * The method can be called any time after <code>prepare()</code>.
     * This allows to insert the Signature element at any position in the
     * Security header.
     * 
     * @param secHeader The secHeader that holds the Signature element.
     */
    public void prependToHeader(WSSecHeader secHeader) {
        WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), sig.getElement());
    }
    
    /**
     * Appends the Signature element to the elements already in the Security
     * header.
     * 
     * The method can be called any time after <code>prepare()</code>.
     * This allows to insert the Signature element at any position in the
     * Security header.
     * 
     * @param secHeader The secHeader that holds the Signature element.
     */
    public void appendToHeader(WSSecHeader secHeader) {
        Element secHeaderElement = secHeader.getSecurityHeader();
        secHeaderElement.appendChild(sig.getElement());
    }
    
    /**
     * Prepend the BinarySecurityToken to the elements already in the Security
     * header.
     * 
     * The method can be called any time after <code>prepare()</code>.
     * This allows to insert the BST element at any position in the Security
     * header.
     * 
     * @param secHeader The security header
     */
    public void prependBSTElementToHeader(WSSecHeader secHeader) {
        if (bstToken != null) {
            WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), bstToken.getElement());
        }
        bstToken = null;
    }

    /**
     * Append the BinarySecurityToken to the security header. 
     * @param secHeader The security header
     */
    public void appendBSTElementToHeader(WSSecHeader secHeader) {
        if (bstToken != null) {
            Element secHeaderElement = secHeader.getSecurityHeader();
            secHeaderElement.appendChild(bstToken.getElement());
        }
        bstToken = null;
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
    public void computeSignature() throws WSSecurityException {
        boolean remove = WSDocInfoStore.store(wsDocInfo);
        try {
            if (secretKey == null) {
                sig.sign(crypto.getPrivateKey(user, password));
            } else {
                sig.sign(sig.createSecretKey(secretKey));                    
            }
            signatureValue = sig.getSignatureValue();
        } catch (Exception ex) {
            throw new WSSecurityException(
                WSSecurityException.FAILED_SIGNATURE, null, null, ex
            );
        } finally {
            if (remove) {
                WSDocInfoStore.delete(wsDocInfo);
            }
        }

    }

    
    /**
     * Set the wsu:Id on the element argument
     */
    public static String setWsuId(Element element, WSSConfig wssConfig) {
        String id = element.getAttributeNS(WSConstants.WSU_NS, "Id");

        if ((id == null) || (id.length() == 0)) {
            id = wssConfig.getIdAllocator().createId("id-", element);
            String prefix = 
                WSSecurityUtil.setNamespace(element, WSConstants.WSU_NS, WSConstants.WSU_PREFIX);
            element.setAttributeNS(WSConstants.WSU_NS, prefix + ":Id", id);
        }
        return id;
    }
    
    /**
     * Create an STRTransformationParameters element
     */
    public static Element createSTRParameter(Document doc) {
        Element transformParam = 
            doc.createElementNS(
                WSConstants.WSSE_NS,
                WSConstants.WSSE_PREFIX + ":TransformationParameters"
            );

        Element canonElem = 
            doc.createElementNS(
                WSConstants.SIG_NS,
                WSConstants.SIG_PREFIX + ":CanonicalizationMethod"
            );

        canonElem.setAttribute("Algorithm", Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        transformParam.appendChild(canonElem);
        return transformParam;
    }

    
    /**
     * Create a new XMLSignature object with inclusive prefixes
     * @param doc The document that will own the signature
     * @param securityHeader The security header in which to insert the signature
     * @param c14nAlgorithm The canonicalization algorithm to use in SignedInfo
     * @param signatureAlg The signature algorithm to use in SignedInfo
     * @return A new XMLSignature object with inclusive prefixes
     * @throws WSSecurityException
     */
    public static XMLSignature createXMLSignatureInclusivePrefixes(
        Document doc,
        Element securityHeader,
        String c14nAlgorithm,
        String signatureAlg
    ) throws WSSecurityException {
        Element canonElem = 
            XMLUtils.createElementInSignatureSpace(doc, Constants._TAG_CANONICALIZATIONMETHOD);
        canonElem.setAttribute(Constants._ATT_ALGORITHM, c14nAlgorithm);

        Set prefixes = getInclusivePrefixes(securityHeader, false);
        InclusiveNamespaces inclusiveNamespaces = new InclusiveNamespaces(doc, prefixes);
        canonElem.appendChild(inclusiveNamespaces.getElement());

        try {
            SignatureAlgorithm signatureAlgorithm = new SignatureAlgorithm(doc, signatureAlg);
            return new XMLSignature(doc, null, signatureAlgorithm.getElement(), canonElem);
        } catch (XMLSecurityException e) {
            log.error("", e);
            throw new WSSecurityException(
                WSSecurityException.FAILED_SIGNATURE, "noXMLSig", null, e
            );
        }
    }
    
    
    /**
     * Get the set of inclusive prefixes from the DOM Element argument 
     */
    public static Set getInclusivePrefixes(Element target) {
        return getInclusivePrefixes(target, true);
    }
    
    
    /**
     * Get the set of inclusive prefixes from the DOM Element argument 
     */
    public static Set getInclusivePrefixes(Element target, boolean excludeVisible) {
        Set result = new HashSet();
        Node parent = target;
        while (!(Node.DOCUMENT_NODE == parent.getParentNode().getNodeType())) {
            parent = parent.getParentNode();
            NamedNodeMap attributes = parent.getAttributes();
            for (int i = 0; i < attributes.getLength(); i++) {
                Node attribute = attributes.item(i);
                if (attribute.getNamespaceURI() != null
                    && attribute.getNamespaceURI().equals(
                        org.apache.ws.security.WSConstants.XMLNS_NS
                    )
                ) {
                    if (attribute.getNodeName().equals("xmlns")) {
                        result.add("#default");
                    } else {
                        result.add(attribute.getLocalName());
                    }
                }
            }
        }

        if (excludeVisible == true) {
            NamedNodeMap attributes = target.getAttributes();
            for (int i = 0; i < attributes.getLength(); i++) {
                Node attribute = attributes.item(i);
                if (attribute.getNamespaceURI() != null
                    && attribute.getNamespaceURI().equals(
                        org.apache.ws.security.WSConstants.XMLNS_NS
                    )
                ) {
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
     * Set the name (uri) of the signature encryption algorithm to use.
     * 
     * If the algorithm is not set then an automatic detection of the signature
     * algorithm to use is performed during the <code>prepare()</code>
     * method. Refer to WSConstants which algorithms are supported.
     * 
     * @param algo the name of the signature algorithm
     * @see WSConstants#RSA
     * @see WSConstants#DSA
     */
    public void setSignatureAlgorithm(String algo) {
        sigAlgo = algo;
    }

    /**
     * Get the name (uri) of the signature algorithm that is being used.
     * 
     * Call this method after <code>prepare</code> to get the information
     * which signature algorithm was automatically detected if no signature
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
     * @param algo Is the name of the signature algorithm
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
     * @return the digest algorithm to use
     */
    public String getDigestAlgo() {
        return digestAlgo;
    }

    /**
     * Set the string that defines which digest algorithm to use. The default is SHA-1.
     * 
     * @param digestAlgo the digestAlgo to set
     */
    public void setDigestAlgo(String digestAlgo) {
        this.digestAlgo = digestAlgo;
    }
    
    
    /**
     * Returns the computed Signature value.
     * 
     * Call this method after <code>computeSignature()</code> or <code>build()</code>
     * methods were called.
     * 
     * @return Returns the signatureValue.
     */
    public byte[] getSignatureValue() {
        return signatureValue;
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
     * Set the secret key to use
     * @param secretKey the secret key to use
     */
    public void setSecretKey(byte[] secretKey) {
        this.secretKey = secretKey;
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
     * Returns the SignatureElement.
     * The method can be called any time after <code>prepare()</code>.
     * @return The DOM Element of the signature.
     */
    public Element getSignatureElement() {
        return sig.getElement();
    }
    
    /**
     * Returns the BST Token element.
     * The method can be called any time after <code>prepare()</code>.
     * @return the BST Token element
     */
    public Element getBinarySecurityTokenElement() {
        if (bstToken != null) {
            return bstToken.getElement();
        }
        return null;
    }

    private String getSHA1(byte[] input) throws WSSecurityException {
        try {
            MessageDigest sha = WSSecurityUtil.resolveMessageDigest();
            sha.reset();
            sha.update(input);
            byte[] data = sha.digest();
            
            return Base64.encode(data);
        } catch (NoSuchAlgorithmException e) {
            throw new WSSecurityException(
                WSSecurityException.UNSUPPORTED_ALGORITHM, null, null, e
            );
        }
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
                certs = crypto.getCertificates(user);
            } else {
                certs = new X509Certificate[] {useThisCert};
            }
            if (certs == null || certs.length <= 0) {
                throw new WSSecurityException(
                        WSSecurityException.FAILURE,
                        "noUserCertsFound", 
                        new Object[] { user, "signature" }
                );
            }
            certUri = wssConfig.getIdAllocator().createSecureId("X509-", certs[0]);  
            //
            // If no signature algorithm was set try to detect it according to the
            // data stored in the certificate.
            //
            if (sigAlgo == null) {
                String pubKeyAlgo = certs[0].getPublicKey().getAlgorithm();
                log.debug("Automatic signature algorithm detection: " + pubKeyAlgo);
                if (pubKeyAlgo.equalsIgnoreCase("DSA")) {
                    sigAlgo = XMLSignature.ALGO_ID_SIGNATURE_DSA;
                } else if (pubKeyAlgo.equalsIgnoreCase("RSA")) {
                    sigAlgo = XMLSignature.ALGO_ID_SIGNATURE_RSA;
                } else {
                    throw new WSSecurityException(
                        WSSecurityException.FAILURE,
                        "unknownSignatureAlgorithm",
                        new Object[] {pubKeyAlgo}
                    );
                }
            }
        }
        return certs;
    }
    
}
