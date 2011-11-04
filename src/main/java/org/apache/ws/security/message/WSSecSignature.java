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

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoType;
import org.apache.ws.security.message.token.BinarySecurity;
import org.apache.ws.security.message.token.DOMX509Data;
import org.apache.ws.security.message.token.DOMX509IssuerSerial;
import org.apache.ws.security.message.token.KerberosSecurity;
import org.apache.ws.security.message.token.PKIPathSecurity;
import org.apache.ws.security.message.token.Reference;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.message.token.X509Security;
import org.apache.ws.security.transform.STRTransform;
import org.apache.ws.security.util.Base64;
import org.apache.ws.security.util.WSSecurityUtil;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.XMLSignContext;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.ExcC14NParameterSpec;


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
public class WSSecSignature extends WSSecSignatureBase {

    private static org.apache.commons.logging.Log log = 
        org.apache.commons.logging.LogFactory.getLog(WSSecSignature.class);

    protected boolean useSingleCert = true;
    protected String sigAlgo = null;
    protected String canonAlgo = WSConstants.C14N_EXCL_OMIT_COMMENTS;
    protected byte[] signatureValue = null;
    protected Document document = null;
    protected WSDocInfo wsDocInfo = null;
    protected String certUri = null;
    protected String keyInfoUri = null;
    protected SecurityTokenReference secRef = null;
    protected String strUri = null;
    protected BinarySecurity bstToken = null;
    
    protected KeyInfoFactory keyInfoFactory;
    protected XMLSignatureFactory signatureFactory;
    protected KeyInfo keyInfo;
    protected CanonicalizationMethod c14nMethod;
    protected XMLSignature sig;
    protected byte[] secretKey = null;
    protected String customTokenValueType;
    protected String customTokenId;
    
    private String encrKeySha1value = null;
    private Crypto crypto = null;
    private String digestAlgo = WSConstants.SHA1;
    private X509Certificate useThisCert = null;
    private Element securityHeader = null;
    private boolean useCustomSecRef;

    public WSSecSignature() {
        super();
        init();
    }
    
    public WSSecSignature(WSSConfig config) {
        super(config);
        init();
    }
    
    private void init() {
        // Try to install the Santuario Provider - fall back to the JDK provider if this does
        // not work
        try {
            signatureFactory = XMLSignatureFactory.getInstance("DOM", "ApacheXMLDSig");
        } catch (NoSuchProviderException ex) {
            signatureFactory = XMLSignatureFactory.getInstance("DOM");
        }
        try {
            keyInfoFactory = KeyInfoFactory.getInstance("DOM", "ApacheXMLDSig");
        } catch (NoSuchProviderException ex) {
            keyInfoFactory = KeyInfoFactory.getInstance("DOM");
        }
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
        securityHeader = secHeader.getSecurityHeader();
        
        //
        // At first get the security token (certificate) according to the parameters.
        //
        X509Certificate[] certs = getSigningCerts();

        try {
            C14NMethodParameterSpec c14nSpec = null;
            if (getWsConfig().isWsiBSPCompliant() && canonAlgo.equals(WSConstants.C14N_EXCL_OMIT_COMMENTS)) {
                List<String> prefixes = 
                    getInclusivePrefixes(secHeader.getSecurityHeader(), false);
                c14nSpec = new ExcC14NParameterSpec(prefixes);
            }
            
           c14nMethod = signatureFactory.newCanonicalizationMethod(canonAlgo, c14nSpec);
        } catch (Exception ex) {
            log.error("", ex);
            throw new WSSecurityException(
                WSSecurityException.FAILED_SIGNATURE, "noXMLSig", null, ex
            );
        }

        keyInfoUri = getWsConfig().getIdAllocator().createSecureId("KI-", keyInfo);
        if (!useCustomSecRef) {
            secRef = new SecurityTokenReference(doc);
            strUri = getWsConfig().getIdAllocator().createSecureId("STR-", secRef);
            secRef.setID(strUri);
            
            //
            // Get an initialized XMLSignature element.
            //
            
            //
            // Prepare and setup the token references for this Signature
            //
            switch (keyIdentifierType) {
            case WSConstants.BST_DIRECT_REFERENCE:
                Reference ref = new Reference(document);
                ref.setURI("#" + certUri);
                if (!useSingleCert) {
                    bstToken = new PKIPathSecurity(document);
                    ((PKIPathSecurity) bstToken).setX509Certificates(certs, crypto);
                    secRef.addTokenType(PKIPathSecurity.PKI_TYPE);
                } else {
                    bstToken = new X509Security(document);
                    ((X509Security) bstToken).setX509Certificate(certs[0]);
                }
                ref.setValueType(bstToken.getValueType());
                secRef.setReference(ref);
                bstToken.setID(certUri);
                wsDocInfo.addTokenElement(bstToken.getElement(), false);
                break;
    
            case WSConstants.ISSUER_SERIAL:
                String issuer = certs[0].getIssuerX500Principal().getName();
                java.math.BigInteger serialNumber = certs[0].getSerialNumber();
                DOMX509IssuerSerial domIssuerSerial = 
                    new DOMX509IssuerSerial(doc, issuer, serialNumber);
                DOMX509Data domX509Data = new DOMX509Data(doc, domIssuerSerial);
                secRef.setX509Data(domX509Data);
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
                    byte[] digestBytes = WSSecurityUtil.generateDigest(secretKey);
                    secRef.setKeyIdentifierEncKeySHA1(Base64.encode(digestBytes));
                }
                secRef.addTokenType(WSConstants.WSS_ENC_KEY_VALUE_TYPE);
                break;
    
            case WSConstants.CUSTOM_SYMM_SIGNING :
                Reference refCust = new Reference(document);
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
                Reference refCustd = new Reference(document);
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
                    KeyValue keyValue = keyInfoFactory.newKeyValue(publicKey);
                    keyInfo = 
                        keyInfoFactory.newKeyInfo(
                            java.util.Collections.singletonList(keyValue), keyInfoUri
                        );
                } catch (java.security.KeyException ex) {
                    log.error("", ex);
                    throw new WSSecurityException(
                        WSSecurityException.FAILED_SIGNATURE, "noXMLSig", null, ex
                    );
                }
                break;
            default:
                throw new WSSecurityException(WSSecurityException.FAILURE, "unsupportedKeyId");
            }
        }
        
        if (keyIdentifierType != WSConstants.KEY_VALUE) {
            XMLStructure structure = new DOMStructure(secRef.getElement());
            wsDocInfo.addTokenElement(secRef.getElement(), false);
            keyInfo = 
                keyInfoFactory.newKeyInfo(
                    java.util.Collections.singletonList(structure), keyInfoUri
                );
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
            parts = new ArrayList<WSEncryptionPart>(1);
            String soapNamespace = WSSecurityUtil.getSOAPNamespace(doc.getDocumentElement());
            WSEncryptionPart encP = 
                new WSEncryptionPart(
                    WSConstants.ELEM_BODY, 
                    soapNamespace, 
                    "Content"
                );
            parts.add(encP);
        } else {
            for (WSEncryptionPart part : parts) {
                if ("STRTransform".equals(part.getName()) && part.getId() == null) {
                    part.setId(strUri);
                }
            }
        }

        List<javax.xml.crypto.dsig.Reference> referenceList = 
            addReferencesToSign(parts, secHeader);

        computeSignature(referenceList);
        
        //
        // if we have a BST prepend it in front of the Signature according to
        // strict layout rules.
        //
        if (bstToken != null) {
            prependBSTElementToHeader(secHeader);
        }

        return doc;
    }
    
    
    /**
     * This method adds references to the Signature.
     * 
     * @param references The list of references to sign
     * @param secHeader The Security Header
     * @throws WSSecurityException
     */
    public List<javax.xml.crypto.dsig.Reference> addReferencesToSign(
        List<WSEncryptionPart> references, 
        WSSecHeader secHeader
    ) throws WSSecurityException {
        return 
            addReferencesToSign(
                document, 
                references,
                wsDocInfo,
                signatureFactory, 
                secHeader, 
                getWsConfig(), 
                digestAlgo
            );
    }

    /**
     * Returns the SignatureElement.
     * The method can be called any time after <code>prepare()</code>.
     * @return The DOM Element of the signature.
     */
    public Element getSignatureElement() {
        return
            WSSecurityUtil.getDirectChildElement(
                securityHeader,
                WSConstants.SIG_LN,
                WSConstants.SIG_NS
            );
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
                key = WSSecurityUtil.prepareSecretKey(sigAlgo, secretKey);
            }
            SignatureMethod signatureMethod = 
                signatureFactory.newSignatureMethod(sigAlgo, null);
            SignedInfo signedInfo = 
                signatureFactory.newSignedInfo(c14nMethod, signatureMethod, referenceList);
            
            sig = signatureFactory.newXMLSignature(
                    signedInfo, 
                    keyInfo,
                    null,
                    getWsConfig().getIdAllocator().createId("SIG-", null),
                    null);
            
            //
            // Figure out where to insert the signature element
            //
            XMLSignContext signContext = null;
            if (prepend) {
                if (siblingElement == null) {
                    Node child = securityHeader.getFirstChild();
                    while (child != null && child.getNodeType() != Node.ELEMENT_NODE) {
                        child = child.getNextSibling();
                    } 
                    siblingElement = (Element)child;
                }
                if (siblingElement == null) {
                    signContext = new DOMSignContext(key, securityHeader);
                } else {
                    signContext = new DOMSignContext(key, securityHeader, siblingElement);
                }
            } else {
                signContext = new DOMSignContext(key, securityHeader);
            }
            
            signContext.putNamespacePrefix(WSConstants.SIG_NS, WSConstants.SIG_PREFIX);
            if (WSConstants.C14N_EXCL_OMIT_COMMENTS.equals(canonAlgo)) {
                signContext.putNamespacePrefix(
                    WSConstants.C14N_EXCL_OMIT_COMMENTS, 
                    WSConstants.C14N_EXCL_OMIT_COMMENTS_PREFIX
                );
            }
            signContext.setProperty(STRTransform.TRANSFORM_WS_DOC_INFO, wsDocInfo);
            wsDocInfo.setCallbackLookup(callbackLookup);
            
            // Add the elements to sign to the Signature Context
            wsDocInfo.setTokensOnContext((DOMSignContext)signContext);
            if (secRef != null && secRef.getElement() != null) {
                WSSecurityUtil.storeElementInContext((DOMSignContext)signContext, secRef.getElement());
            }
            sig.sign(signContext);
            
            signatureValue = sig.getSignatureValue().getValue();
        } catch (Exception ex) {
            log.error(ex);
            throw new WSSecurityException(
                WSSecurityException.FAILED_SIGNATURE, null, null, ex
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
     * XML Canonicalization is used by default. Refer to WSConstants which
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
     * Set the string that defines which digest algorithm to use. 
     * The default is Constants.ALGO_ID_DIGEST_SHA1.
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
     * Get the id of the BST generated  during <code>prepare()</code>.
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
    
    /**
     * @return the URI associated with the SecurityTokenReference
     * (must be called after {@link #prepare(Document, Crypto, WSSecHeader)}
     */
    public String getSecurityTokenReferenceURI() {
        return strUri;
    }
    
    /**
     * Get the SecurityTokenReference to be used in the KeyInfo element.
     */
    public SecurityTokenReference getSecurityTokenReference() {
        return secRef;
    }
    
    /**
     * Set the SecurityTokenReference to be used in the KeyInfo element. If this
     * method is not called, a SecurityTokenRefence will be generated.
     */
    public void setSecurityTokenReference(SecurityTokenReference secRef) {
        useCustomSecRef = true;
        this.secRef = secRef;
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
                certs = crypto.getX509Certificates(cryptoType);
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
            certUri = getWsConfig().getIdAllocator().createSecureId("X509-", certs[0]);  
            //
            // If no signature algorithm was set try to detect it according to the
            // data stored in the certificate.
            //
            if (sigAlgo == null) {
                String pubKeyAlgo = certs[0].getPublicKey().getAlgorithm();
                log.debug("Automatic signature algorithm detection: " + pubKeyAlgo);
                if (pubKeyAlgo.equalsIgnoreCase("DSA")) {
                    sigAlgo = WSConstants.DSA;
                } else if (pubKeyAlgo.equalsIgnoreCase("RSA")) {
                    sigAlgo = WSConstants.RSA;
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
