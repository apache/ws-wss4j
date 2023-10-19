package org.apache.wss4j.dom.processor;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.str.STRParser;

import java.security.PublicKey;
import java.security.cert.X509Certificate;

/**
 * The result of resolving the KeyInfoType element to locate the public key (with the X509Certificate chain if given )
 * The result is either a PublicKey or/and an X509Certificate chain with the STRParser.REFERENCE_TYPE.
 */
public class CertificateResult {

    /**
     * CertificateResult builder class.
     */
    static final class Builder {
        private X509Certificate[] certs;
        private PublicKey publicKey;
        private STRParser.REFERENCE_TYPE referenceType;

        protected Builder() {
        }

        public static Builder create() {
            return new Builder();
        }

        public Builder certificates(X509Certificate[] certs) {
            this.certs = certs;
            return this;
        }

        public Builder publicKey(PublicKey publicKey) {
            this.publicKey = publicKey;
            return this;
        }

        public Builder certificatesReferenceType(STRParser.REFERENCE_TYPE referenceType) {
            this.referenceType = referenceType;
            return this;
        }

        /**
         * Method to build the CertificateResult object.
         *
         * @return the CertificateResult object
         * @throws WSSecurityException if the result is empty.
         */
        public CertificateResult build() throws WSSecurityException {
            if (publicKey == null && (certs == null || certs.length < 1 || certs[0] == null)) {
                throw new WSSecurityException(
                        WSSecurityException.ErrorCode.FAILURE,
                        "noCertsFound",
                        new Object[] {"decryption (KeyId)"});
            }
            if (certs != null && certs.length > 0) {
                publicKey = certs[0].getPublicKey();
            }

            return new CertificateResult(certs, publicKey, referenceType);
        }
    }

    private X509Certificate[] certs;
    private PublicKey publicKey;
    private STRParser.REFERENCE_TYPE referenceType;

    protected CertificateResult(X509Certificate[] certs, PublicKey publicKey, STRParser.REFERENCE_TYPE referenceType) {
        this.certs = certs;
        this.publicKey = publicKey;
        this.referenceType = referenceType;
    }

    public X509Certificate[] getCerts() {
        return certs;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public STRParser.REFERENCE_TYPE getCertificatesReferenceType() {
        return referenceType;
    }
}
