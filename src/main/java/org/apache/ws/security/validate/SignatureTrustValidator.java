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

import javax.security.auth.callback.CallbackHandler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;

/**
 * This class verifies trust in a credential used to verify a signature, which is extracted
 * from the Credential passed to the validate method.
 */
public class SignatureTrustValidator implements Validator {
    
    private static Log LOG = LogFactory.getLog(SignatureTrustValidator.class.getName());
    protected Crypto crypto;
    
    /**
     * Validate the credential argument. It must contain a non-null X509Certificate chain
     * or a PublicKey. A Crypto implementation is also required to be set.
     * 
     * This implementation first attempts to verify trust on the certificate (chain). If
     * this is not successful, then it will attempt to verify trust on the Public Key.
     * 
     * @param credential the Credential to be validated
     * @throws WSSecurityException on a failed validation
     */
    public void validate(Credential credential) throws WSSecurityException {
        if (credential == null) {
            throw new WSSecurityException(WSSecurityException.FAILURE, "noCredential");
        }
        X509Certificate[] certs = credential.getCertificates();
        PublicKey publicKey = credential.getPublicKey();
        if (crypto == null) {
            throw new WSSecurityException(WSSecurityException.FAILURE, "noSigCryptoFile");
        }
        
        if (certs != null && certs.length > 0) {
            validateCertificates(certs);
            boolean trust = false;
            if (certs.length == 1) {
                trust = verifyTrustInCert(certs);
            } else {
                trust = verifyTrustInCerts(certs);
            }
            if (trust) {
                return;
            }
        }
        if (publicKey != null) {
            boolean trust = validatePublicKey(publicKey);
            if (trust) {
                return;
            }
        }
        throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
    }
    
    /**
     * Set a WSSConfig instance used to extract configured options used to 
     * validate credentials. This method is not currently used for this implementation.
     * @param wssConfig a WSSConfig instance
     */
    public void setWSSConfig(WSSConfig wssConfig) {
        //
    }
    
    /**
     * Set a Crypto instance used to validate credentials. This is required for this
     * implementation.
     * @param crypto a Crypto instance used to validate credentials
     */
    public void setCrypto(Crypto crypto) {
        this.crypto = crypto;
    }
    
    /**
     * Set a CallbackHandler instance used to validate credentials. This method is not 
     * currently used for this implementation.
     * @param callbackHandler a CallbackHandler instance used to validate credentials
     */
    public void setCallbackHandler(CallbackHandler callbackHandler) {
        //
    }
    
    /**
     * Validate the certificates by checking the validity of each cert
     * @throws WSSecurityException
     */
    private void validateCertificates(X509Certificate[] certificates) throws WSSecurityException {
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
    private boolean verifyTrustInCert(X509Certificate[] certificates) throws WSSecurityException {
        X509Certificate cert = certificates[0];
        
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
    private boolean verifyTrustInCerts(X509Certificate[] certificates) throws WSSecurityException {
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
     * Validate a public key
     * @throws WSSecurityException
     */
    private boolean validatePublicKey(PublicKey publicKey) throws WSSecurityException {
        return crypto.verifyTrust(publicKey);
    }
    
}
