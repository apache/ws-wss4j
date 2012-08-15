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

package org.apache.ws.security.validate;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoType;
import org.apache.ws.security.handler.RequestData;

/**
 * This class verifies trust in a credential used to verify a signature, which is extracted
 * from the Credential passed to the validate method.
 */
public class SignatureTrustValidator implements Validator {
    
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(SignatureTrustValidator.class);
    
    /**
     * Validate the credential argument. It must contain a non-null X509Certificate chain
     * or a PublicKey. A Crypto implementation is also required to be set.
     * 
     * This implementation first attempts to verify trust on the certificate (chain). If
     * this is not successful, then it will attempt to verify trust on the Public Key.
     * 
     * @param credential the Credential to be validated
     * @param data the RequestData associated with the request
     * @throws WSSecurityException on a failed validation
     */
    public Credential validate(Credential credential, RequestData data) throws WSSecurityException {
        if (credential == null) {
            throw new WSSecurityException(WSSecurityException.FAILURE, "noCredential");
        }
        X509Certificate[] certs = credential.getCertificates();
        PublicKey publicKey = credential.getPublicKey();
        Crypto crypto = getCrypto(data);
        if (crypto == null) {
            throw new WSSecurityException(WSSecurityException.FAILURE, "noSigCryptoFile");
        }
        
        if (certs != null && certs.length > 0) {
            validateCertificates(certs);
            boolean trust = false;
            boolean enableRevocation = data.isRevocationEnabled();
            if (certs.length == 1) {
                trust = verifyTrustInCert(certs[0], crypto, data, enableRevocation);
            } else {
                trust = verifyTrustInCerts(certs, crypto, data, enableRevocation);
            }
            if (trust) {
                return credential;
            }
        }
        if (publicKey != null) {
            boolean trust = validatePublicKey(publicKey, crypto);
            if (trust) {
                return credential;
            }
        }
        throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
    }


    protected Crypto getCrypto(RequestData data) {
        return data.getSigCrypto();
    }


    /**
     * Validate the certificates by checking the validity of each cert
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
                WSSecurityException.FAILED_CHECK, "invalidCert", null, e
            );
        } catch (CertificateNotYetValidException e) {
            throw new WSSecurityException(
                WSSecurityException.FAILED_CHECK, "invalidCert", null, e
            );
        }
    }
    
    @Deprecated
    protected boolean verifyTrustInCert(X509Certificate cert, Crypto crypto) 
        throws WSSecurityException {
        return verifyTrustInCert(cert, crypto, new RequestData(), false);
    }
    
    @Deprecated
    protected boolean verifyTrustInCert(X509Certificate cert, Crypto crypto, boolean enableRevocation) 
        throws WSSecurityException {
        return verifyTrustInCert(cert, crypto, new RequestData(), enableRevocation);
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
     * @param crypto A crypto instance to use for trust validation
     * @param data A RequestData instance
     * @param enableRevocation Whether revocation is enabled or not
     * @return true if the certificate is trusted, false if not
     * @throws WSSecurityException
     */
    protected boolean verifyTrustInCert(
        X509Certificate cert, 
        Crypto crypto,
        RequestData data,
        boolean enableRevocation
    ) throws WSSecurityException {
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
        if (!enableRevocation && isCertificateInKeyStore(crypto, cert)) {
            return true;
        }

        //
        // SECOND step - Search for the issuer cert (chain) of the transmitted certificate in the 
        // keystore or the truststore
        //
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.SUBJECT_DN);
        cryptoType.setSubjectDN(issuerString);
        X509Certificate[] foundCerts = crypto.getX509Certificates(cryptoType);

        // If the certs have not been found, the issuer is not in the keystore/truststore
        // As a direct result, do not trust the transmitted certificate
        if (foundCerts == null || foundCerts.length < 1) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(
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
        if (LOG.isDebugEnabled()) {
            LOG.debug(
                "Preparing to validate certificate path for issuer " + issuerString
            );
        }
        //
        // Form a certificate chain from the transmitted certificate
        // and the certificate(s) of the issuer from the keystore/truststore
        //
        X509Certificate[] x509certs = new X509Certificate[foundCerts.length + 1];
        x509certs[0] = cert;
        for (int j = 0; j < foundCerts.length; j++) {
            x509certs[j + 1] = (X509Certificate)foundCerts[j];
        }

        //
        // Use the validation method from the crypto to check whether the subjects' 
        // certificate was really signed by the issuer stated in the certificate
        //
        if (crypto.verifyTrust(x509certs, enableRevocation)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(
                    "Certificate path has been verified for certificate with subject " 
                     + subjectString
                );
            }
            Collection<Pattern> subjectCertConstraints = data.getSubjectCertConstraints();
            if (matches(cert, subjectCertConstraints)) {
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
     * Check to see if the certificate argument is in the keystore
     * @param crypto A Crypto instance to use for trust validation
     * @param cert The certificate to check
     * @return true if cert is in the keystore
     * @throws WSSecurityException
     */
    protected boolean isCertificateInKeyStore(
        Crypto crypto,
        X509Certificate cert
    ) throws WSSecurityException {
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
            if (LOG.isDebugEnabled()) {
                LOG.debug(
                    "Direct trust for certificate with " + cert.getSubjectX500Principal().getName()
                );
            }
            return true;
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug(
                "No certificate found for subject from issuer with " + issuerString 
                + " (serial " + issuerSerial + ")"
            );
        }
        return false;
    }
    
    @Deprecated
    protected boolean verifyTrustInCerts(
        X509Certificate[] certificates, 
        Crypto crypto
    ) throws WSSecurityException {
        return verifyTrustInCerts(certificates, crypto, new RequestData(), false);
    }
    
    @Deprecated
    protected boolean verifyTrustInCerts(
        X509Certificate[] certificates, 
        Crypto crypto,
        boolean enableRevocation
    ) throws WSSecurityException {
        return verifyTrustInCerts(certificates, crypto, new RequestData(), enableRevocation);
    }
    
    /**
     * Evaluate whether the given certificate chain should be trusted.
     * 
     * @param certificates the certificate chain that should be validated against the keystore
     * @param crypto A Crypto instance
     * @param data A RequestData instance
     * @param enableRevocation Whether revocation is enabled or not
     * @return true if the certificate chain is trusted, false if not
     * @throws WSSecurityException
     */
    protected boolean verifyTrustInCerts(
        X509Certificate[] certificates, 
        Crypto crypto,
        RequestData data,
        boolean enableRevocation
    ) throws WSSecurityException {
        if (certificates == null || certificates.length < 2) {
            return false;
        }
        
        String subjectString = certificates[0].getSubjectX500Principal().getName();
        //
        // Use the validation method from the crypto to check whether the subjects' 
        // certificate was really signed by the issuer stated in the certificate
        //
        if (crypto.verifyTrust(certificates, enableRevocation)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(
                    "Certificate path has been verified for certificate with subject " 
                    + subjectString
                );
            }
            Collection<Pattern> subjectCertConstraints = data.getSubjectCertConstraints();
            if (matches(certificates[0], subjectCertConstraints)) {
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
     * Validate a public key
     * @throws WSSecurityException
     */
    protected boolean validatePublicKey(PublicKey publicKey, Crypto crypto) 
        throws WSSecurityException {
        return crypto.verifyTrust(publicKey);
    }
    
    /**
     * @return      true if the certificate's SubjectDN matches the constraints defined in the
     *              subject DNConstraints; false, otherwise. The certificate subject DN only
     *              has to match ONE of the subject cert constraints (not all).
     */
    protected boolean
    matches(
        final java.security.cert.X509Certificate cert,
        final Collection<Pattern> subjectDNPatterns
    ) {
        if (subjectDNPatterns.isEmpty()) {
            LOG.warn("No Subject DN Certificate Constraints were defined. This could be a security issue");
        }
        if (!subjectDNPatterns.isEmpty()) {
            if (cert == null) {
                LOG.debug("The certificate is null so no constraints matching was possible");
                return false;
            }
            String subjectName = cert.getSubjectX500Principal().getName();
            boolean subjectMatch = false;
            for (Pattern subjectDNPattern : subjectDNPatterns) {
                final Matcher matcher = subjectDNPattern.matcher(subjectName);
                if (matcher.matches()) {
                    LOG.debug("Subject DN " + subjectName + " matches with pattern " + subjectDNPattern);
                    subjectMatch = true;
                    break;
                }
            }
            if (!subjectMatch) {
                return false;
            }
        }
        
        return true;
    }
    
}
