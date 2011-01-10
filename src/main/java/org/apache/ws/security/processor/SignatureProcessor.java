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

package org.apache.ws.security.processor;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.PublicKeyCallback;
import org.apache.ws.security.PublicKeyPrincipal;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSDataRef;
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.WSUsernameTokenPrincipal;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.message.DOMURIDereferencer;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.str.STRParser;
import org.apache.ws.security.str.SignatureSTRParser;
import org.apache.ws.security.transform.STRTransform;
import org.apache.ws.security.transform.STRTransformUtil;
import org.apache.ws.security.util.WSSecurityUtil;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.NodeSetData;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.XMLValidateContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;

import java.math.BigInteger;
import java.security.Key;
import java.security.PublicKey;
import java.security.Principal;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SignatureProcessor implements Processor {
    private static Log LOG = LogFactory.getLog(SignatureProcessor.class.getName());
    
    private XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM");
    
    private KeyInfoFactory keyInfoFactory = KeyInfoFactory.getInstance("DOM");

    public List<WSSecurityEngineResult> handleToken(
        Element elem, 
        Crypto crypto, 
        Crypto decCrypto, 
        CallbackHandler cb, 
        WSDocInfo wsDocInfo, 
        WSSConfig wsc
    ) throws WSSecurityException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Found signature element");
        }
        Element keyInfoElement = 
            WSSecurityUtil.getDirectChildElement(
                elem,
                "KeyInfo",
                WSConstants.SIG_NS
            );
        X509Certificate[] certs = null;
        Principal principal = null;
        PublicKey publicKey = null;
        byte[] secretKey = null;
        String signatureMethod = getSignatureMethod(elem);
        if (keyInfoElement == null) {
            certs = getDefaultCerts(crypto);
            principal = certs[0].getSubjectX500Principal();
        } else {
            Element strElement = 
                WSSecurityUtil.getDirectChildElement(
                    keyInfoElement,
                    SecurityTokenReference.SECURITY_TOKEN_REFERENCE,
                    WSConstants.WSSE_NS
                );
            if (strElement == null) {
                publicKey = parseKeyValue(keyInfoElement);
                principal = validatePublicKey(cb, publicKey);
            } else {
                STRParser strParser = new SignatureSTRParser();
                Map<String, Object> parameters = new HashMap<String, Object>();
                parameters.put(SignatureSTRParser.SIGNATURE_METHOD, signatureMethod);
                parameters.put(
                    SignatureSTRParser.SECRET_KEY_LENGTH, new Integer(wsc.getSecretKeyLength())
                );
                strParser.parseSecurityTokenReference(
                    strElement, crypto, cb, wsDocInfo, parameters
                );
                principal = strParser.getPrincipal();
                certs = strParser.getCertificates();
                publicKey = strParser.getPublicKey();
                secretKey = strParser.getSecretKey();
                validateCredentials(certs, crypto);
            }
        }
        
        //
        // Check that we have a certificate, a public key or a secret key with which to
        // perform signature verification
        //
        if ((certs == null || certs.length == 0 || certs[0] == null) 
            && secretKey == null
            && publicKey == null) {
            throw new WSSecurityException(WSSecurityException.FAILED_CHECK);
        }
        
        XMLSignature xmlSignature = 
            verifyXMLSignature(elem, certs, publicKey, secretKey, signatureMethod, wsDocInfo);
        byte[] signatureValue = xmlSignature.getSignatureValue().getValue();
        String c14nMethod = xmlSignature.getSignedInfo().getCanonicalizationMethod().getAlgorithm();
        List<WSDataRef> dataRefs =  
            buildProtectedRefs(
                elem.getOwnerDocument(), xmlSignature.getSignedInfo(), wsDocInfo
            );
        
        int actionPerformed = WSConstants.SIGN;
        if (principal instanceof WSUsernameTokenPrincipal) {
            actionPerformed = WSConstants.UT_SIGN;
        }

        WSSecurityEngineResult result = new WSSecurityEngineResult(
                actionPerformed, principal,
                certs, dataRefs, signatureValue);
        result.put(WSSecurityEngineResult.TAG_SIGNATURE_METHOD, signatureMethod);
        result.put(WSSecurityEngineResult.TAG_CANONICALIZATION_METHOD, c14nMethod);
        result.put(WSSecurityEngineResult.TAG_ID, elem.getAttribute("Id"));
        result.put(WSSecurityEngineResult.TAG_SECRET, secretKey);
        wsDocInfo.addResult(result);
        return java.util.Collections.singletonList(result);
    }
    
    /**
     * Get the default certificates from the KeyStore
     * @param crypto The Crypto object containing the default alias
     * @return The default certificates
     * @throws WSSecurityException
     */
    private X509Certificate[] getDefaultCerts(
        Crypto crypto
    ) throws WSSecurityException {
        if (crypto == null) {
            throw new WSSecurityException(WSSecurityException.FAILURE, "noSigCryptoFile");
        }
        if (crypto.getDefaultX509Alias() != null) {
            return crypto.getCertificates(crypto.getDefaultX509Alias());
        } else {
            throw new WSSecurityException(
                WSSecurityException.INVALID_SECURITY, "unsupportedKeyInfo"
            );
        }
    }
    
    /**
     * Validate the credentials that were extracted from the SecurityTokenReference
     * TODO move into Validator
     * @throws WSSecurityException if the credentials are invalid
     */
    private void validateCredentials(
        X509Certificate[] certs,
        Crypto crypto
    ) throws WSSecurityException {
        //
        // Validate certificates and verify trust
        //
        validateCertificates(certs);
        if (certs != null) {
            boolean trust = false;
            if (certs.length == 1) {
                trust = verifyTrust(certs[0], crypto);
            } else if (certs.length > 1) {
                trust = verifyTrust(certs, crypto);
            }
            if (!trust) {
                throw new WSSecurityException(WSSecurityException.FAILED_CHECK);
            }
        }
    }
    
    /**
     * Validate an array of certificates by checking the validity of each cert
     * @param certsToValidate The array of certificates to validate
     * @throws WSSecurityException
     */
    private static void validateCertificates(
        X509Certificate[] certsToValidate
    ) throws WSSecurityException {
        if (certsToValidate != null && certsToValidate.length > 0) {
            try {
                for (int i = 0; i < certsToValidate.length; i++) {
                    certsToValidate[i].checkValidity();
                }
            } catch (CertificateExpiredException e) {
                throw new WSSecurityException(
                    WSSecurityException.FAILED_CHECK, "invalidCert", null, e
                );
            } catch (CertificateNotYetValidException e) {
                throw new WSSecurityException(
                    WSSecurityException.FAILED_CHECK, "invalidCert", null, e
                );
            }
        }
    }
    
    
    /**
     * Evaluate whether a given certificate should be trusted.
     * 
     * Policy used in this implementation:
     * 1. Search the keystore for the transmitted certificate
     * 2. Search the keystore for a connection to the transmitted certificate
     * (that is, search for certificate(s) of the issuer of the transmitted certificate
     * 3. Verify the trust path for those certificates found because the search for the issuer 
     * might be fooled by a phony DN (String!)
     *
     * @param cert the certificate that should be validated against the keystore
     * @return true if the certificate is trusted, false if not
     * @throws WSSecurityException
     */
    private static boolean verifyTrust(X509Certificate cert, Crypto crypto) 
        throws WSSecurityException {

        // If no certificate was transmitted, do not trust the signature
        if (cert == null) {
            return false;
        }

        String subjectString = cert.getSubjectX500Principal().getName();
        String issuerString = cert.getIssuerX500Principal().getName();
        BigInteger issuerSerial = cert.getSerialNumber();

        if (LOG.isDebugEnabled()) {
            LOG.debug("Transmitted certificate has subject " + subjectString);
            LOG.debug(
                "Transmitted certificate has issuer " + issuerString + " (serial " 
                + issuerSerial + ")"
            );
        }

        //
        // FIRST step - Search the keystore for the transmitted certificate
        //
        if (crypto.isCertificateInKeyStore(cert)) {
            return true;
        }

        //
        // SECOND step - Search for the issuer of the transmitted certificate in the 
        // keystore or the truststore
        //
        String[] aliases = crypto.getAliasesForDN(issuerString);

        // If the alias has not been found, the issuer is not in the keystore/truststore
        // As a direct result, do not trust the transmitted certificate
        if (aliases == null || aliases.length < 1) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(
                    "No aliases found in keystore for issuer " + issuerString 
                    + " of certificate for " + subjectString
                );
            }
            return false;
        }

        //
        // THIRD step
        // Check the certificate trust path for every alias of the issuer found in the 
        // keystore/truststore
        //
        for (int i = 0; i < aliases.length; i++) {
            String alias = aliases[i];

            if (LOG.isDebugEnabled()) {
                LOG.debug(
                    "Preparing to validate certificate path with alias " + alias 
                    + " for issuer " + issuerString
                );
            }

            // Retrieve the certificate(s) for the alias from the keystore/truststore
            X509Certificate[] certs = crypto.getCertificates(alias);

            // If no certificates have been found, there has to be an error:
            // The keystore/truststore can find an alias but no certificate(s)
            if (certs == null || certs.length < 1) {
                throw new WSSecurityException(
                    "Could not get certificates for alias " + alias
                );
            }

            //
            // Form a certificate chain from the transmitted certificate
            // and the certificate(s) of the issuer from the keystore/truststore
            //
            X509Certificate[] x509certs = new X509Certificate[certs.length + 1];
            x509certs[0] = cert;
            for (int j = 0; j < certs.length; j++) {
                x509certs[j + 1] = certs[j];
            }

            //
            // Use the validation method from the crypto to check whether the subjects' 
            // certificate was really signed by the issuer stated in the certificate
            //
            if (crypto.validateCertPath(x509certs)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug(
                        "Certificate path has been verified for certificate with subject " 
                        + subjectString
                    );
                }
                return true;
            }
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug(
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
    private static boolean verifyTrust(X509Certificate[] certificates, Crypto crypto) 
        throws WSSecurityException {
        String subjectString = certificates[0].getSubjectX500Principal().getName();
        //
        // Use the validation method from the crypto to check whether the subjects' 
        // certificate was really signed by the issuer stated in the certificate
        //
        if (certificates != null && certificates.length > 1
            && crypto.validateCertPath(certificates)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(
                    "Certificate path has been verified for certificate with subject " 
                    + subjectString
                );
            }
            return true;
        }
        
        if (LOG.isDebugEnabled()) {
            LOG.debug(
                "Certificate path could not be verified for certificate with subject " 
                + subjectString
            );
        }
            
        return false;
    }
    
    
    private PublicKey parseKeyValue(
        Element keyInfoElement
    ) throws WSSecurityException {
        KeyValue keyValue = null;
        try {
            //
            // Look for a KeyValue object
            //
            keyValue = getKeyValue(keyInfoElement);
        } catch (javax.xml.crypto.MarshalException ex) {
            throw new WSSecurityException(WSSecurityException.FAILED_CHECK, null, null, ex);
        } 

        if (keyValue != null) {
            try {
                //
                // Look for a Public Key in Key Value
                //
                return keyValue.getPublicKey();
            } catch (java.security.KeyException ex) {
                LOG.error(ex.getMessage(), ex);
                throw new WSSecurityException(WSSecurityException.FAILED_CHECK, null, null, ex);
            }     
        } else {
            throw new WSSecurityException(
                    WSSecurityException.INVALID_SECURITY, "unsupportedKeyInfo"
            );
        }
    }
    
    /**
     * Get the KeyValue object from the KeyInfo DOM element if it exists
     */
    private KeyValue getKeyValue(
        Element keyInfoElement
    ) throws MarshalException {
        XMLStructure keyInfoStructure = new DOMStructure(keyInfoElement);
        KeyInfo keyInfo = keyInfoFactory.unmarshalKeyInfo(keyInfoStructure);
        List<?> list = keyInfo.getContent();

        for (int i = 0; i < list.size(); i++) {
            XMLStructure xmlStructure = (XMLStructure) list.get(i);
            if (xmlStructure instanceof KeyValue) {
                return (KeyValue)xmlStructure;
            }
        }
        return null;
    }
    
    /**
     * Validate a public key via a CallbackHandler
     * @param cb The CallbackHandler object
     * @param publicKey The PublicKey to validate
     * @return A PublicKeyPrincipal object encapsulating the public key after successful 
     *         validation
     * @throws WSSecurityException
     */
    private static Principal validatePublicKey(
        CallbackHandler cb,
        PublicKey publicKey
    ) throws WSSecurityException {
        PublicKeyCallback pwcb = 
            new PublicKeyCallback(publicKey);
        try {
            Callback[] callbacks = new Callback[]{pwcb};
            cb.handle(callbacks);
            if (!pwcb.isVerified()) {
                throw new WSSecurityException(
                    WSSecurityException.FAILED_AUTHENTICATION, null, null, null
                );
            }
        } catch (Exception e) {
            throw new WSSecurityException(
                WSSecurityException.FAILED_AUTHENTICATION, null, null, e
            );
        }
        return new PublicKeyPrincipal(publicKey);
    }
    

    /**
     * Verify the WS-Security signature.
     * 
     * The functions at first checks if then <code>KeyInfo</code> that is
     * contained in the signature contains standard X509 data. If yes then
     * get the certificate data via the standard <code>KeyInfo</code> methods.
     * 
     * Otherwise, if the <code>KeyInfo</code> info does not contain X509 data, check
     * if we can find a <code>wsse:SecurityTokenReference</code> element. If yes, the next
     * step is to check how to get the certificate. Two methods are currently supported
     * here:
     * <ul>
     * <li> A URI reference to a binary security token contained in the <code>wsse:Security
     * </code> header.  If the dereferenced token is
     * of the correct type the contained certificate is extracted.
     * </li>
     * <li> Issuer name an serial number of the certificate. In this case the method
     * looks up the certificate in the keystore via the <code>crypto</code> parameter.
     * </li>
     * </ul>
     * 
     * @param elem        the XMLSignature DOM Element.
     * @param crypto      the object that implements the access to the keystore and the
     *                    handling of certificates.
     * @param protectedRefs A list of (references) to the signed elements
     * @param cb CallbackHandler instance to extract key passwords
     * @return the subject principal of the validated X509 certificate (the
     *         authenticated subject). The calling function may use this
     *         principal for further authentication or authorization.
     * @throws WSSecurityException
     */
    private XMLSignature verifyXMLSignature(
        Element elem,
        X509Certificate[] certs,
        PublicKey publicKey,
        byte[] secretKey,
        String signatureMethod,
        WSDocInfo wsDocInfo
    ) throws WSSecurityException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Verify XML Signature");
        }
        
        //
        // Perform the signature verification and build up a List of elements that the
        // signature refers to
        //
        Key key = null;
        if (certs != null && certs[0] != null) {
            key = certs[0].getPublicKey();
        } else if (publicKey != null) {
            key = publicKey;
        } else {
            key = WSSecurityUtil.prepareSecretKey(signatureMethod, secretKey);
        }
        
        XMLValidateContext context = new DOMValidateContext(key, elem);
        context.setProperty("javax.xml.crypto.dsig.cacheReference", Boolean.TRUE);
        URIDereferencer dereferencer = new DOMURIDereferencer();
        ((DOMURIDereferencer)dereferencer).setWsDocInfo(wsDocInfo);
        context.setURIDereferencer(dereferencer);
        context.setProperty(STRTransform.TRANSFORM_WS_DOC_INFO, wsDocInfo);
        try {
            XMLSignature xmlSignature = signatureFactory.unmarshalXMLSignature(context);
            boolean signatureOk = xmlSignature.validate(context);
            if (signatureOk) {
                return xmlSignature;
            } else {
                //
                // Log the exact signature error
                //
                if (LOG.isDebugEnabled()) {
                    LOG.debug("XML Signature verification has failed");
                    boolean signatureValidationCheck = 
                        xmlSignature.getSignatureValue().validate(context);
                    LOG.debug("Signature Validation check: " + signatureValidationCheck);
                    java.util.Iterator<?> referenceIterator = 
                        xmlSignature.getSignedInfo().getReferences().iterator();
                    while (referenceIterator.hasNext()) {
                        Reference reference = (Reference)referenceIterator.next();
                        boolean referenceValidationCheck = reference.validate(context);
                        String id = reference.getId();
                        if (id == null) {
                            id = reference.getURI();
                        }
                        LOG.debug("Reference " + id + " check: " + referenceValidationCheck);
                    }
                }
                
                throw new WSSecurityException(WSSecurityException.FAILED_CHECK);
            }
        } catch (Exception ex) {
            throw new WSSecurityException(
                WSSecurityException.FAILED_CHECK, null, null, ex
            );
        }
    }
    
    
    /**
     * Get the signature method algorithm URI from the associated signature element.
     * @param signatureElement The signature element
     * @return the signature method URI
     */
    private static String getSignatureMethod(
        Element signatureElement
    ) {
        Element signedInfoElement = 
            WSSecurityUtil.getDirectChildElement(
                signatureElement,
                "SignedInfo",
                WSConstants.SIG_NS
            );
        if (signedInfoElement != null) {
            Element signatureMethodElement = 
                WSSecurityUtil.getDirectChildElement(
                    signedInfoElement,
                    "SignatureMethod",
                    WSConstants.SIG_NS
                );
            if (signatureMethodElement != null) {
                return signatureMethodElement.getAttributeNS(null, "Algorithm");
            }
        }
        return null;
    }
    
    
    /**
     * This method digs into the Signature element to get the elements that
     * this Signature covers. Build the QName of these Elements and return them
     * to caller
     * @param doc The owning document
     * @param signedInfo The SignedInfo object
     * @param protectedRefs A list of protected references
     * @return A list of protected references
     * @throws WSSecurityException
     */
    private List<WSDataRef> buildProtectedRefs(
        Document doc,
        SignedInfo signedInfo,
        WSDocInfo wsDocInfo
    ) throws WSSecurityException {
        List<WSDataRef> protectedRefs = new java.util.ArrayList<WSDataRef>();
        List<?> referencesList = signedInfo.getReferences();
        for (int i = 0; i < referencesList.size(); i++) {
            Reference siRef = (Reference)referencesList.get(i);
            String uri = siRef.getURI();
            
            if (!"".equals(uri)) {
                Element se = null;
                
                List<?> transformsList = siRef.getTransforms();
                
                for (int j = 0; j < transformsList.size(); j++) {
                    
                    Transform transform = (Transform)transformsList.get(j);
                    
                    if (STRTransform.TRANSFORM_URI.equals(transform.getAlgorithm())) {
                        NodeSetData data = (NodeSetData)siRef.getDereferencedData();
                        if (data != null) {
                            java.util.Iterator<?> iter = data.iterator();
                            
                            Node securityTokenReference = null;
                            while (iter.hasNext()) {
                                Node node = (Node)iter.next();
                                if ("SecurityTokenReference".equals(node.getLocalName())) {
                                    securityTokenReference = node;
                                    break;
                                }
                            }
                            
                            if (securityTokenReference != null) {
                                SecurityTokenReference secTokenRef = 
                                    new SecurityTokenReference((Element)securityTokenReference);
                                se = STRTransformUtil.dereferenceSTR(doc, secTokenRef, wsDocInfo);
                            }
                        }
                    }
                }
                
                if (se == null) {
                    se = 
                        WSSecurityUtil.findElementById(
                            doc.getDocumentElement(), uri, false
                        );
                }
                if (se == null) {
                    throw new WSSecurityException(WSSecurityException.FAILED_CHECK);
                }
                
                WSDataRef ref = new WSDataRef();
                ref.setWsuId(uri);
                ref.setProtectedElement(se);
                ref.setAlgorithm(signedInfo.getSignatureMethod().getAlgorithm());
                ref.setDigestAlgorithm(siRef.getDigestMethod().getAlgorithm());
                ref.setXpath(ReferenceListProcessor.getXPath(se));
                protectedRefs.add(ref);
            }
        }
        return protectedRefs;
    }
    
    

}
