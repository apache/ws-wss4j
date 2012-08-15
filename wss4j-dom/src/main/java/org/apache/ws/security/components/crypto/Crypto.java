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
package org.apache.ws.security.components.crypto;

import org.apache.ws.security.WSSecurityException;

import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.security.auth.callback.CallbackHandler;

public interface Crypto {
    
    //
    // Accessor methods
    //
    
    /**
     * Get the crypto provider associated with this implementation
     * @return the crypto provider
     */
    String getCryptoProvider();
    
    /**
     * Set the crypto provider associated with this implementation
     * @param provider the crypto provider to set
     */
    void setCryptoProvider(String provider);
    
    /**
     * Retrieves the identifier name of the default certificate. This should be the certificate 
     * that is used for signature and encryption. This identifier corresponds to the certificate 
     * that should be used whenever KeyInfo is not present in a signed or an encrypted 
     * message. May return null. The identifier is implementation specific, e.g. it could be the
     * KeyStore alias.
     *
     * @return name of the default X509 certificate.
     */
    String getDefaultX509Identifier() throws WSSecurityException;
    
    /**
     * Sets the identifier name of the default certificate. This should be the certificate 
     * that is used for signature and encryption. This identifier corresponds to the certificate 
     * that should be used whenever KeyInfo is not present in a signed or an encrypted 
     * message. The identifier is implementation specific, e.g. it could be the KeyStore alias.
     *
     * @param identifier name of the default X509 certificate.
     */
    void setDefaultX509Identifier(String identifier);
    
    /**
     * Sets the CertificateFactory instance on this Crypto instance
     *
     * @param provider the CertificateFactory provider name
     * @param certFactory the CertificateFactory the CertificateFactory instance to set
     */
    void setCertificateFactory(String provider, CertificateFactory certFactory);
    
    /**
     * Get the CertificateFactory instance on this Crypto instance
     *
     * @return Returns a <code>CertificateFactory</code> to construct
     *         X509 certificates
     * @throws org.apache.ws.security.WSSecurityException
     */
    CertificateFactory getCertificateFactory() throws WSSecurityException;
    
    //
    // Base Crypto functionality methods
    //
    
    /**
     * Load a X509Certificate from the input stream.
     *
     * @param in The <code>InputStream</code> containing the X509 data
     * @return An X509 certificate
     * @throws WSSecurityException
     */
    X509Certificate loadCertificate(InputStream in) throws WSSecurityException;
    
    /**
     * Reads the SubjectKeyIdentifier information from the certificate.
     * <p/>
     * If the the certificate does not contain a SKI extension then
     * try to compute the SKI according to RFC3280 using the
     * SHA-1 hash value of the public key. The second method described
     * in RFC3280 is not support. Also only RSA public keys are supported.
     * If we cannot compute the SKI throw a WSSecurityException.
     *
     * @param cert The certificate to read SKI
     * @return The byte array containing the binary SKI data
     */
    byte[] getSKIBytesFromCert(X509Certificate cert) throws WSSecurityException;
    
    /**
     * Get a byte array given an array of X509 certificates.
     * <p/>
     *
     * @param certs The certificates to convert
     * @return The byte array for the certificates
     * @throws WSSecurityException
     */
    byte[] getBytesFromCertificates(X509Certificate[] certs) throws WSSecurityException;

    /**
     * Construct an array of X509Certificate's from the byte array.
     *
     * @param data The <code>byte</code> array containing the X509 data
     * @return An array of X509 certificates
     * @throws WSSecurityException
     */
    X509Certificate[] getCertificatesFromBytes(byte[] data) throws WSSecurityException;
    
    //
    // Implementation-specific Crypto functionality methods
    //
    
    /**
     * Get an X509Certificate (chain) corresponding to the CryptoType argument. The supported
     * types are as follows:
     * 
     * TYPE.ISSUER_SERIAL - A certificate (chain) is located by the issuer name and serial number
     * TYPE.THUMBPRINT_SHA1 - A certificate (chain) is located by the SHA1 of the (root) cert
     * TYPE.SKI_BYTES - A certificate (chain) is located by the SKI bytes of the (root) cert
     * TYPE.SUBJECT_DN - A certificate (chain) is located by the Subject DN of the (root) cert
     * TYPE.ALIAS - A certificate (chain) is located by an alias. This alias is implementation
     * specific, for example - it could be a java KeyStore alias.
     */
    X509Certificate[] getX509Certificates(CryptoType cryptoType) throws WSSecurityException;
    
    /**
     * Get the implementation-specific identifier corresponding to the cert parameter, e.g. the
     * identifier could be a KeyStore alias.
     * @param cert The X509Certificate for which to search for an identifier
     * @return the identifier corresponding to the cert parameter
     * @throws WSSecurityException
     */
    String getX509Identifier(X509Certificate cert) throws WSSecurityException;
    
    /**
     * Gets the private key corresponding to the certificate.
     *
     * @param certificate The X509Certificate corresponding to the private key
     * @param callbackHandler The callbackHandler needed to get the password
     * @return The private key
     */
    PrivateKey getPrivateKey(
        X509Certificate certificate, CallbackHandler callbackHandler
    ) throws WSSecurityException;
       
    /**
     * Gets the private key corresponding to the identifier.
     *
     * @param identifier The implementation-specific identifier corresponding to the key
     * @param password The password needed to get the key
     * @return The private key
     */
    PrivateKey getPrivateKey(
        String identifier, String password
    ) throws WSSecurityException;
    
    /**
     * Evaluate whether a given certificate chain should be trusted.
     *
     * @param certs Certificate chain to validate
     * @return true if the certificate chain is valid, false otherwise
     * @throws WSSecurityException
     */
    @Deprecated
    boolean verifyTrust(X509Certificate[] certs) throws WSSecurityException;
    
    /**
     * Evaluate whether a given certificate chain should be trusted.
     *
     * @param certs Certificate chain to validate
     * @param enableRevocation whether to enable CRL verification or not
     * @return true if the certificate chain is valid, false otherwise
     * @throws WSSecurityException
     */
    boolean verifyTrust(
        X509Certificate[] certs, boolean enableRevocation
    ) throws WSSecurityException;
    
    /**
     * Evaluate whether a given public key should be trusted.
     * 
     * @param publicKey The PublicKey to be evaluated
     * @return whether the PublicKey parameter is trusted or not
     */
    boolean verifyTrust(PublicKey publicKey) throws WSSecurityException;

}
