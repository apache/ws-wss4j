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

package org.apache.ws.security.str;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.CustomTokenPrincipal;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.message.token.BinarySecurity;
import org.apache.ws.security.message.token.DerivedKeyToken;
import org.apache.ws.security.message.token.PKIPathSecurity;
import org.apache.ws.security.message.token.SecurityContextToken;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.message.token.UsernameToken;
import org.apache.ws.security.message.token.X509Security;
import org.apache.ws.security.processor.EncryptedKeyProcessor;
import org.apache.ws.security.saml.SAMLKeyInfo;
import org.apache.ws.security.saml.SAMLUtil;
import org.apache.ws.security.util.WSSecurityUtil;
import org.opensaml.SAMLAssertion;
import org.w3c.dom.Element;

import java.math.BigInteger;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.xml.namespace.QName;

public class SignatureSTRParser implements STRParser {
    
    private static final Log LOG = LogFactory.getLog(SignatureSTRParser.class.getName());
    
    private X509Certificate[] certs;
    
    private byte[] secretKey;
    
    private PublicKey publicKey;
    
    private Principal principal;
    
    private boolean validateCertChain;
    
    private Crypto crypto;
    
    public void parseSecurityTokenReference(
        Element strElement,
        String algorithm,
        Crypto crypto,
        CallbackHandler cb,
        WSDocInfo wsDocInfo,
        WSSConfig wssConfig
    ) throws WSSecurityException {
        this.crypto = crypto;
        SecurityTokenReference secRef = new SecurityTokenReference(strElement);
        //
        // Here we get some information about the document that is being
        // processed, in particular the crypto implementation, and already
        // detected BST that may be used later during dereferencing.
        //
        if (secRef.containsReference()) {
            org.apache.ws.security.message.token.Reference ref = secRef.getReference();

            String uri = ref.getURI();
            if (uri.charAt(0) == '#') {
                uri = uri.substring(1);
            }
            WSSecurityEngineResult result = wsDocInfo.getResult(uri);
            if (result == null) {
                Element token = 
                    secRef.getTokenElement(strElement.getOwnerDocument(), wsDocInfo, cb);
                QName el = new QName(token.getNamespaceURI(), token.getLocalName());
                if (el.equals(WSSecurityEngine.BINARY_TOKEN)) {
                    certs = getCertificatesTokenReference(token, crypto);
                    if (certs != null && certs.length > 1) {
                        validateCertChain = true;
                    }
                } else if (el.equals(WSSecurityEngine.SAML_TOKEN)) {
                    if (crypto == null) {
                        throw new WSSecurityException(
                                WSSecurityException.FAILURE, "noSigCryptoFile"
                        );
                    }
                    SAMLKeyInfo samlKi = SAMLUtil.getSAMLKeyInfo(token, crypto, cb);
                    certs = samlKi.getCerts();
                    secretKey = samlKi.getSecret();
                    principal = createPrincipalFromSAMLKeyInfo(samlKi);
                } else if (el.equals(WSSecurityEngine.ENCRYPTED_KEY)){
                    EncryptedKeyProcessor proc = 
                        new EncryptedKeyProcessor();
                    WSDocInfo docInfo = new WSDocInfo(token.getOwnerDocument());
                    List<WSSecurityEngineResult> encrResult =
                        proc.handleToken(token, null, crypto, cb, docInfo, null);
                    secretKey = 
                        (byte[])encrResult.get(0).get(
                                WSSecurityEngineResult.TAG_DECRYPTED_KEY
                        );
                    principal = new CustomTokenPrincipal(token.getAttribute("Id"));
                } else {
                    String id = secRef.getReference().getURI();
                    secretKey = getSecretKeyFromCustomToken(id, cb);
                    principal = new CustomTokenPrincipal(id);
                }
            } else {
                int action = ((Integer)result.get(WSSecurityEngineResult.TAG_ACTION)).intValue();
                if (WSConstants.UT == action) {
                    UsernameToken usernameToken = 
                        (UsernameToken)result.get(WSSecurityEngineResult.TAG_USERNAME_TOKEN);

                    if (usernameToken.isDerivedKey()) {
                        secretKey = usernameToken.getDerivedKey();
                    } else {
                        secretKey = usernameToken.getSecretKey(wssConfig.getSecretKeyLength());
                    }
                    principal = usernameToken.createPrincipal();
                } else if (WSConstants.BST == action) {
                    certs = 
                        (X509Certificate[])result.get(WSSecurityEngineResult.TAG_X509_CERTIFICATES);
                    if (certs != null && certs.length > 1) {
                        validateCertChain = true;
                    }
                } else if (WSConstants.ENCR == action) {
                    secretKey = (byte[])result.get(WSSecurityEngineResult.TAG_DECRYPTED_KEY);
                    String id = (String)result.get(WSSecurityEngineResult.TAG_ID);
                    principal = new CustomTokenPrincipal(id);
                } else if (WSConstants.SCT == action) {
                    secretKey = (byte[])result.get(WSSecurityEngineResult.TAG_SECRET);
                    SecurityContextToken sct = 
                        (SecurityContextToken)result.get(
                                WSSecurityEngineResult.TAG_SECURITY_CONTEXT_TOKEN
                        );
                    principal = new CustomTokenPrincipal(sct.getIdentifier());
                } else if (WSConstants.DKT == action) {
                    DerivedKeyToken dkt = 
                        (DerivedKeyToken)result.get(WSSecurityEngineResult.TAG_DERIVED_KEY_TOKEN);
                    int keyLength = dkt.getLength();
                    if (keyLength <= 0) {
                        keyLength = WSSecurityUtil.getKeyLength(algorithm);
                    }
                    byte[] secret = (byte[])result.get(WSSecurityEngineResult.TAG_SECRET);
                    secretKey = dkt.deriveKey(keyLength, secret); 
                    principal = dkt.createPrincipal();
                } else if (WSConstants.ST_UNSIGNED == action) {
                    if (crypto == null) {
                        throw new WSSecurityException(
                                WSSecurityException.FAILURE, "noSigCryptoFile"
                        );
                    }
                    Element samlElement = wsDocInfo.getTokenElement(uri);
                    SAMLKeyInfo keyInfo = 
                        SAMLUtil.getSAMLKeyInfo(samlElement, crypto, cb);
                    certs = keyInfo.getCerts();
                    secretKey = keyInfo.getSecret();
                    publicKey = keyInfo.getPublicKey();
                    principal = createPrincipalFromSAMLKeyInfo(keyInfo);
                }
            }
        } else if (secRef.containsX509Data() || secRef.containsX509IssuerSerial()) {
            certs = secRef.getX509IssuerSerial(crypto);
        } else if (secRef.containsKeyIdentifier()) {
            if (secRef.getKeyIdentifierValueType().equals(SecurityTokenReference.ENC_KEY_SHA1_URI)) {
                String id = secRef.getKeyIdentifierValue();
                secretKey = getSecretKeyFromEncKeySHA1KI(id, cb);
                principal = new CustomTokenPrincipal(id);
            } else if (WSConstants.WSS_SAML_KI_VALUE_TYPE.equals(secRef.getKeyIdentifierValueType())) { 
                Element token = 
                    secRef.getKeyIdentifierTokenElement(strElement.getOwnerDocument(), wsDocInfo, cb);

                if (crypto == null) {
                    throw new WSSecurityException(
                            WSSecurityException.FAILURE, "noSigCryptoFile"
                    );
                }
                SAMLKeyInfo samlKi = SAMLUtil.getSAMLKeyInfo(token, crypto, cb);
                certs = samlKi.getCerts();
                secretKey = samlKi.getSecret();
                publicKey = samlKi.getPublicKey();
                principal = createPrincipalFromSAMLKeyInfo(samlKi);
            } else {
                certs = secRef.getKeyIdentifier(crypto);
            }
        } else {
            throw new WSSecurityException(
                    WSSecurityException.INVALID_SECURITY,
                    "unsupportedKeyInfo", 
                    new Object[]{strElement.toString()}
            );
        }
    }
    
    public void validateCredentials() throws WSSecurityException {
        //
        // Validate certificates and verify trust
        //
        validateCertificates(certs);
        if (certs != null) {
            if (principal == null) {
                principal = certs[0].getSubjectX500Principal();
            }
            boolean trust = false;
            if (!validateCertChain || certs.length == 1) {
                trust = verifyTrust(certs[0], crypto);
            } else if (validateCertChain && certs.length > 1) {
                trust = verifyTrust(certs, crypto);
            }
            if (!trust) {
                throw new WSSecurityException(WSSecurityException.FAILED_CHECK);
            }
        }
    }
    
    public X509Certificate[] getCertificates() {
        return certs;
    }
    
    public Principal getPrincipal() {
        return principal;
    }
    
    public PublicKey getPublicKey() {
        return publicKey;
    }
    
    public byte[] getSecretKey() {
        return secretKey;
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
    
    
    /**
     * Extracts the certificate(s) from the Binary Security token reference.
     *
     * @param elem The element containing the binary security token. This is
     *             either X509 certificate(s) or a PKIPath.
     * @return an array of X509 certificates
     * @throws WSSecurityException
     */
    private static X509Certificate[] getCertificatesTokenReference(Element elem, Crypto crypto)
        throws WSSecurityException {
        if (crypto == null) {
            throw new WSSecurityException(WSSecurityException.FAILURE, "noSigCryptoFile");
        }
        BinarySecurity token = createSecurityToken(elem);
        if (token instanceof PKIPathSecurity) {
            return ((PKIPathSecurity) token).getX509Certificates(crypto);
        } else {
            X509Certificate cert = ((X509Security) token).getX509Certificate(crypto);
            return new X509Certificate[]{cert};
        }
    }


    /**
     * Checks the <code>element</code> and creates appropriate binary security object.
     *
     * @param element The XML element that contains either a <code>BinarySecurityToken
     *                </code> or a <code>PKIPath</code> element. Other element types a not
     *                supported
     * @return the BinarySecurity object, either a <code>X509Security</code> or a
     *         <code>PKIPathSecurity</code> object.
     * @throws WSSecurityException
     */
    private static BinarySecurity createSecurityToken(Element element) throws WSSecurityException {

        String type = element.getAttribute("ValueType");
        if (X509Security.X509_V3_TYPE.equals(type)) {
            X509Security x509 = new X509Security(element);
            return (BinarySecurity) x509;
        } else if (PKIPathSecurity.getType().equals(type)) {
            PKIPathSecurity pkiPath = new PKIPathSecurity(element);
            return (BinarySecurity) pkiPath;
        }
        throw new WSSecurityException(
            WSSecurityException.UNSUPPORTED_SECURITY_TOKEN,
            "unsupportedBinaryTokenType", 
            new Object[]{type}
        );
    }
    
    /**
     * A method to create a Principal from a SAML KeyInfo
     * @param samlKeyInfo The SAML KeyInfo object
     * @return A principal
     */
    private static Principal createPrincipalFromSAMLKeyInfo(
        SAMLKeyInfo samlKeyInfo
    ) {
        X509Certificate[] samlCerts = samlKeyInfo.getCerts();
        Principal principal = null;
        if (samlCerts != null && samlCerts.length > 0) {
            principal = samlCerts[0].getSubjectX500Principal();
        } else {
            final SAMLAssertion assertion = samlKeyInfo.getAssertion();
            principal = new CustomTokenPrincipal(assertion.getId());
            ((CustomTokenPrincipal)principal).setTokenObject(assertion);
        }
        return principal;
    }
    
    /**
     * Get the Secret Key from a CallbackHandler for a custom token
     * @param id The id of the element
     * @param cb The CallbackHandler object
     * @return A Secret Key
     * @throws WSSecurityException
     */
    private byte[] getSecretKeyFromCustomToken(
        String id,
        CallbackHandler cb
    ) throws WSSecurityException {
        if (id.charAt(0) == '#') {
            id = id.substring(1);
        }
        WSPasswordCallback pwcb = 
            new WSPasswordCallback(id, WSPasswordCallback.CUSTOM_TOKEN);
        try {
            Callback[] callbacks = new Callback[]{pwcb};
            cb.handle(callbacks);
        } catch (Exception e) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE,
                "noPassword", 
                new Object[] {id}, 
                e
            );
        }

        return pwcb.getKey();
    }
    
    
    /**
     * Get the Secret Key from a CallbackHandler for the Encrypted Key SHA1 case.
     * @param id The id of the element
     * @param cb The CallbackHandler object
     * @return A Secret Key
     * @throws WSSecurityException
     */
    private byte[] getSecretKeyFromEncKeySHA1KI(
        String id,
        CallbackHandler cb
    ) throws WSSecurityException {
        WSPasswordCallback pwcb = 
            new WSPasswordCallback(
                id,
                null,
                SecurityTokenReference.ENC_KEY_SHA1_URI,
                WSPasswordCallback.ENCRYPTED_KEY_TOKEN
            );
        try {
            Callback[] callbacks = new Callback[]{pwcb};
            cb.handle(callbacks);
        } catch (Exception e) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE,
                "noPassword", 
                new Object[] {id}, 
                e
            );
        }
        return pwcb.getKey();
    }
    
    
}
