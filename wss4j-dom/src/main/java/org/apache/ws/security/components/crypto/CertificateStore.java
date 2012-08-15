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

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateEncodingException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.x500.X500Principal;

/**
 * A Crypto implementation based on a simple array of X509Certificate(s). PrivateKeys are not
 * supported, so this cannot be used for signature creation, or decryption.
 */
public class CertificateStore extends CryptoBase {
    
    protected X509Certificate[] trustedCerts;
    
    /**
     * Constructor
     */
    public CertificateStore(X509Certificate[] trustedCerts) {
        this.trustedCerts = trustedCerts;
    }
   
    /**
     * Get an X509Certificate (chain) corresponding to the CryptoType argument. The supported
     * types are as follows:
     * 
     * TYPE.ISSUER_SERIAL - A certificate (chain) is located by the issuer name and serial number
     * TYPE.THUMBPRINT_SHA1 - A certificate (chain) is located by the SHA1 of the (root) cert
     * TYPE.SKI_BYTES - A certificate (chain) is located by the SKI bytes of the (root) cert
     * TYPE.SUBJECT_DN - A certificate (chain) is located by the Subject DN of the (root) cert
     * TYPE.ALIAS - A certificate (chain) is located by an alias. In this case, it duplicates the
     * TYPE.SUBJECT_DN functionality.
     */
    public X509Certificate[] getX509Certificates(CryptoType cryptoType) throws WSSecurityException {
        if (cryptoType == null) {
            return null;
        }
        CryptoType.TYPE type = cryptoType.getType();
        X509Certificate[] certs = null;
        switch (type) {
        case ISSUER_SERIAL: {
            certs = getX509Certificates(cryptoType.getIssuer(), cryptoType.getSerial());
            break;
        }
        case THUMBPRINT_SHA1: {
            certs = getX509Certificates(cryptoType.getBytes());
            break;
        }
        case SKI_BYTES: {
            certs = getX509CertificatesSKI(cryptoType.getBytes());
            break;
        }
        case ALIAS:
        case SUBJECT_DN: {
            certs = getX509CertificatesSubjectDN(cryptoType.getSubjectDN());
            break;
        }
        }
        return certs;
    }
    
    /**
     * Get the implementation-specific identifier corresponding to the cert parameter. In this
     * case, the identifier refers to the subject DN.
     * @param cert The X509Certificate for which to search for an identifier
     * @return the identifier corresponding to the cert parameter
     * @throws WSSecurityException
     */
    public String getX509Identifier(X509Certificate cert) throws WSSecurityException {
        return cert.getSubjectDN().toString();
    }
    
    /**
     * Gets the private key corresponding to the certificate. Not supported.
     *
     * @param certificate The X509Certificate corresponding to the private key
     * @param callbackHandler The callbackHandler needed to get the password
     * @return The private key
     */
    public PrivateKey getPrivateKey(
        X509Certificate certificate, CallbackHandler callbackHandler
    ) throws WSSecurityException {
        return null;
    }
   
    /**
     * Gets the private key corresponding to the identifier. Not supported.
     *
     * @param identifier The implementation-specific identifier corresponding to the key
     * @param password The password needed to get the key
     * @return The private key
     */
    public PrivateKey getPrivateKey(
        String identifier,
        String password
    ) throws WSSecurityException {
        return null;
    }
    
    /**
     * Evaluate whether a given certificate chain should be trusted.
     *
     * @param certs Certificate chain to validate
     * @return true if the certificate chain is valid, false otherwise
     * @throws WSSecurityException
     */
    @Deprecated
    public boolean verifyTrust(X509Certificate[] certs) throws WSSecurityException {
        return verifyTrust(certs, false);
    }
    
    /**
     * Evaluate whether a given certificate chain should be trusted.
     *
     * @param certs Certificate chain to validate
     * @param enableRevocation whether to enable CRL verification or not
     * @return true if the certificate chain is valid, false otherwise
     * @throws WSSecurityException
     */
    public boolean verifyTrust(
        X509Certificate[] certs, 
        boolean enableRevocation
    ) throws WSSecurityException {
        try {
            // Generate cert path
            List<X509Certificate> certList = Arrays.asList(certs);
            CertPath path = getCertificateFactory().generateCertPath(certList);

            Set<TrustAnchor> set = new HashSet<TrustAnchor>();
            if (trustedCerts != null) {
                for (X509Certificate cert : trustedCerts) {
                    TrustAnchor anchor = 
                        new TrustAnchor(cert, cert.getExtensionValue(NAME_CONSTRAINTS_OID));
                    set.add(anchor);
                }
            }

            PKIXParameters param = new PKIXParameters(set);
            param.setRevocationEnabled(enableRevocation);

            // Verify the trust path using the above settings
            String provider = getCryptoProvider();
            CertPathValidator validator = null;
            if (provider == null || provider.length() == 0) {
                validator = CertPathValidator.getInstance("PKIX");
            } else {
                validator = CertPathValidator.getInstance("PKIX", provider);
            }
            validator.validate(path, param);
            return true;
        } catch (java.security.NoSuchProviderException e) {
                throw new WSSecurityException(
                    WSSecurityException.FAILURE, "certpath",
                    new Object[] { e.getMessage() }, e
                );
        } catch (java.security.NoSuchAlgorithmException e) {
                throw new WSSecurityException(
                    WSSecurityException.FAILURE, "certpath", 
                    new Object[] { e.getMessage() }, e
                );
        } catch (java.security.cert.CertificateException e) {
                throw new WSSecurityException(
                    WSSecurityException.FAILURE, "certpath", 
                    new Object[] { e.getMessage() }, e
                );
        } catch (java.security.InvalidAlgorithmParameterException e) {
                throw new WSSecurityException(
                    WSSecurityException.FAILURE, "certpath",
                    new Object[] { e.getMessage() }, e
                );
        } catch (java.security.cert.CertPathValidatorException e) {
                throw new WSSecurityException(
                    WSSecurityException.FAILURE, "certpath",
                    new Object[] { e.getMessage() }, e
                );
        }
    }
    
    /**
     * Evaluate whether a given public key should be trusted.
     * 
     * @param publicKey The PublicKey to be evaluated
     * @return whether the PublicKey parameter is trusted or not
     */
    public boolean verifyTrust(PublicKey publicKey) throws WSSecurityException {
        //
        // If the public key is null, do not trust the signature
        //
        if (publicKey == null) {
            return false;
        }
        
        //
        // Search the trusted certs for the transmitted public key (direct trust)
        //
        for (X509Certificate trustedCert : trustedCerts) {
            if (publicKey.equals(trustedCert.getPublicKey())) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Get an X509 Certificate (chain) according to a given serial number and issuer string.
     *
     * @param issuer The Issuer String
     * @param serialNumber The serial number of the certificate
     * @return the X509 Certificate (chain) that was found
     * @throws WSSecurityException
     */
    private X509Certificate[] getX509Certificates(
        String issuer, 
        BigInteger serialNumber
    ) throws WSSecurityException {
        //
        // Convert the subject DN to a java X500Principal object first. This is to ensure
        // interop with a DN constructed from .NET, where e.g. it uses "S" instead of "ST".
        // Then convert it to a BouncyCastle X509Name, which will order the attributes of
        // the DN in a particular way (see WSS-168). If the conversion to an X500Principal
        // object fails (e.g. if the DN contains "E" instead of "EMAILADDRESS"), then fall
        // back on a direct conversion to a BC X509Name
        //
        Object issuerName = null;
        try {
            X500Principal issuerRDN = new X500Principal(issuer);
            issuerName = createBCX509Name(issuerRDN.getName());
        } catch (java.lang.IllegalArgumentException ex) {
            issuerName = createBCX509Name(issuer);
        }
        
        for (X509Certificate trustedCert : trustedCerts) {
            if (trustedCert.getSerialNumber().compareTo(serialNumber) == 0) {
                Object certName = 
                    createBCX509Name(trustedCert.getIssuerX500Principal().getName());
                if (certName.equals(issuerName)) {
                    return new X509Certificate[]{trustedCert};
                }
            }
        }
        
        return null;
    }
    
    /**
     * Get an X509 Certificate (chain) according to a given Thumbprint.
     *
     * @param thumb The SHA1 thumbprint info bytes
     * @return the X509 certificate (chain) that was found (can be null)
     * @throws WSSecurityException if problems during keystore handling or wrong certificate
     */
    private X509Certificate[] getX509Certificates(byte[] thumb) throws WSSecurityException {
        MessageDigest sha = null;
        
        if (trustedCerts == null) {
            return null;
        }
        
        try {
            sha = MessageDigest.getInstance("SHA1");
        } catch (NoSuchAlgorithmException e) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE, "noSHA1availabe", null, e
            );
        }
        for (X509Certificate trustedCert : trustedCerts) {
            try {
                sha.update(trustedCert.getEncoded());
            } catch (CertificateEncodingException ex) {
                throw new WSSecurityException(
                    WSSecurityException.SECURITY_TOKEN_UNAVAILABLE, "encodeError",
                    null, ex
                );
            }
            byte[] data = sha.digest();

            if (Arrays.equals(data, thumb)) {
                return new X509Certificate[]{trustedCert};
            }
        }
        return null;
    }
    
    /**
     * Get an X509 Certificate (chain) according to a given SubjectKeyIdentifier.
     *
     * @param skiBytes The SKI bytes
     * @return the X509 certificate (chain) that was found (can be null)
     */
    private X509Certificate[] getX509CertificatesSKI(byte[] skiBytes) throws WSSecurityException {
        if (trustedCerts == null) {
            return null;
        }
        for (X509Certificate trustedCert : trustedCerts) {
            byte[] data = getSKIBytesFromCert(trustedCert);
            if (data.length == skiBytes.length && Arrays.equals(data, skiBytes)) {
                return new X509Certificate[]{trustedCert};
            }
        } 
        return null;
    }
    
    /**
     * Get an X509 Certificate (chain) according to a given DN of the subject of the certificate
     *
     * @param subjectDN The DN of subject to look for
     * @return An X509 Certificate (chain) with the same DN as given in the parameters
     * @throws WSSecurityException
     */
    private X509Certificate[] getX509CertificatesSubjectDN(String subjectDN) 
        throws WSSecurityException {
        //
        // Convert the subject DN to a java X500Principal object first. This is to ensure
        // interop with a DN constructed from .NET, where e.g. it uses "S" instead of "ST".
        // Then convert it to a BouncyCastle X509Name, which will order the attributes of
        // the DN in a particular way (see WSS-168). If the conversion to an X500Principal
        // object fails (e.g. if the DN contains "E" instead of "EMAILADDRESS"), then fall
        // back on a direct conversion to a BC X509Name
        //
        Object subject;
        try {
            X500Principal subjectRDN = new X500Principal(subjectDN);
            subject = createBCX509Name(subjectRDN.getName());
        } catch (java.lang.IllegalArgumentException ex) {
            subject = createBCX509Name(subjectDN);
        }
        
        if (trustedCerts != null) {
            for (X509Certificate trustedCert : trustedCerts) {
                X500Principal foundRDN = trustedCert.getSubjectX500Principal();
                Object certName = createBCX509Name(foundRDN.getName());
    
                if (subject.equals(certName)) {
                    return new X509Certificate[]{trustedCert};
                }
            }
        }
        
        return null;
    }
    
}
