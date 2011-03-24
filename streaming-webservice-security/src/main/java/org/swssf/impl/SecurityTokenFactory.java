/**
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.swssf.impl;

import org.apache.commons.codec.binary.Base64;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.BinarySecurityTokenType;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.KeyIdentifierType;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.SecurityTokenReferenceType;
import org.swssf.crypto.Crypto;
import org.swssf.ext.*;
import org.w3._2000._09.xmldsig_.KeyInfoType;
import org.w3._2000._09.xmldsig_.X509DataType;

import javax.security.auth.callback.CallbackHandler;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.*;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

/**
 * Factory to create SecurityToken Objects from keys in XML
 *
 * @author $Author: giger $
 * @version $Revision: 281 $ $Date: 2011-01-04 21:15:27 +0100 (Tue, 04 Jan 2011) $
 */
public class SecurityTokenFactory {

    private static KeyStore cacerts;
    private static final String NAME_CONSTRAINTS_OID = "2.5.29.30";

    private SecurityTokenFactory() {
    }

    public synchronized static SecurityTokenFactory newInstance() throws WSSecurityException {
        if (cacerts == null) {

            InputStream cacertsIs = null;

            try {
                String cacertsPath = System.getProperty("java.home") + "/lib/security/cacerts";
                cacertsIs = new FileInputStream(cacertsPath);
                //todo security property?:
                String cacertsPasswd = "changeit";

                cacerts = KeyStore.getInstance(KeyStore.getDefaultType());
                cacerts.load(cacertsIs, cacertsPasswd.toCharArray());

            } catch (CertificateException e) {
                throw new WSSecurityException(e);
            } catch (NoSuchAlgorithmException e) {
                throw new WSSecurityException(e);
            } catch (KeyStoreException e) {
                throw new WSSecurityException(e);
            } catch (IOException e) {
                throw new WSSecurityException(e);
            } finally {
                if (cacertsIs != null) {
                    try {
                        cacertsIs.close();
                    } catch (IOException e) {
                        //ignore
                    }
                }
            }
        }

        return new SecurityTokenFactory();
    }

    public SecurityToken getSecurityToken(KeyInfoType keyInfoType, Crypto crypto, final CallbackHandler callbackHandler, SecurityContext securityContext) throws WSSecurityException {
        final SecurityTokenReferenceType securityTokenReferenceType = keyInfoType.getSecurityTokenReferenceType();
        if (securityTokenReferenceType == null) {
            throw new WSSecurityException("No SecurityTokenReference found");
        }

        if (securityTokenReferenceType.getX509DataType() != null) {
            return new X509DataSecurityToken(crypto, callbackHandler, securityTokenReferenceType.getX509DataType());
        } /*else if (securityToken instanceof X509IssuerSerialType) {
                        X509IssuerSerialType x509IssuerSerialType = (X509IssuerSerialType) securityToken;
                        //todo this is not supported by outputProcessor but can be implemented. We'll have a look at the spec if this is allowed
                    }*/ else if (securityTokenReferenceType.getKeyIdentifierType() != null) {
            KeyIdentifierType keyIdentifierType = securityTokenReferenceType.getKeyIdentifierType();

            String valueType = keyIdentifierType.getValueType();
            String encodingType = keyIdentifierType.getEncodingType();

            byte[] binaryContent;
            if (Constants.SOAPMESSAGE_NS10_BASE64_ENCODING.equals(encodingType)) {
                binaryContent = org.bouncycastle.util.encoders.Base64.decode(keyIdentifierType.getValue());
            } else {
                binaryContent = keyIdentifierType.getValue().getBytes();
            }

            if (Constants.NS_X509_V3_TYPE.equals(valueType)) {
                return new X509_V3SecurityToken(crypto, callbackHandler, binaryContent);
            } else if (Constants.NS_X509SubjectKeyIdentifier.equals(valueType)) {
                return new X509SubjectKeyIdentifierSecurityToken(crypto, callbackHandler, binaryContent);
            } else if (Constants.NS_THUMBPRINT.equals(valueType)) {
                return new ThumbprintSHA1SecurityToken(crypto, callbackHandler, binaryContent);
            }
        }//todo SAML Token, Custom-Token etc...
        else if (securityTokenReferenceType.getReferenceType() != null) {

            String uri = securityTokenReferenceType.getReferenceType().getURI();
            if (uri == null) {
                throw new WSSecurityException("badReferenceURI");
            }
            uri = Utils.dropReferenceMarker(uri);
            //embedded BST:
            if (securityTokenReferenceType.getReferenceType().getBinarySecurityTokenType() != null
                    && uri.equals(securityTokenReferenceType.getReferenceType().getBinarySecurityTokenType().getId())) {
                BinarySecurityTokenType binarySecurityTokenType = securityTokenReferenceType.getReferenceType().getBinarySecurityTokenType();
                return getSecurityToken(binarySecurityTokenType, crypto, callbackHandler);
            } else {//referenced BST:
                //todo
                //we have to search BST somewhere in the doc. First we will check for a BST already processed and
                //stored in the context. Otherwise we will abort now.                
                SecurityTokenProvider securityTokenProvider = securityContext.getSecurityTokenProvider(uri);
                if (securityTokenProvider == null) {
                    throw new WSSecurityException("No SecurityToken found");
                }
                return securityTokenProvider.getSecurityToken(crypto);
            }
        }
        throw new WSSecurityException("No SecurityToken found");
    }

    public SecurityToken getSecurityToken(BinarySecurityTokenType binarySecurityTokenType, Crypto crypto, CallbackHandler callbackHandler) throws WSSecurityException {

        //only Base64Encoding is supported
        if (!Constants.SOAPMESSAGE_NS10_BASE64_ENCODING.equals(binarySecurityTokenType.getEncodingType())) {
            throw new WSSecurityException("Unsupported BST Encoding: " + binarySecurityTokenType.getEncodingType());
        }

        byte[] securityTokenData = Base64.decodeBase64(binarySecurityTokenType.getValue());

        if (Constants.NS_X509_V3_TYPE.equals(binarySecurityTokenType.getValueType())) {
            return new X509_V3SecurityToken(crypto, callbackHandler, securityTokenData);
        } else if (Constants.NS_X509PKIPathv1.equals(binarySecurityTokenType.getValueType())) {
            return new X509PKIPathv1SecurityToken(crypto, callbackHandler, securityTokenData);
        } else {
            throw new WSSecurityException("unsupportedBinaryTokenType" + binarySecurityTokenType.getValueType());
        }
    }

    abstract class AbstractSecurityToken implements SecurityToken {

        private Crypto crypto;
        private CallbackHandler callbackHandler;

        protected AbstractSecurityToken(Crypto crypto, CallbackHandler callbackHandler) {
            this.crypto = crypto;
            this.callbackHandler = callbackHandler;
        }

        public Crypto getCrypto() {
            return crypto;
        }

        public CallbackHandler getCallbackHandler() {
            return callbackHandler;
        }
    }

    public abstract class X509SecurityToken extends AbstractSecurityToken {
        private X509Certificate x509Certificate = null;

        protected X509SecurityToken(Crypto crypto, CallbackHandler callbackHandler) {
            super(crypto, callbackHandler);
        }

        public boolean isAsymmetric() {
            return true;
        }

        public Key getSecretKey(String algorithmURI) throws WSSecurityException {
            try {
                //todo overall caching...not just here
                WSPasswordCallback pwCb = new WSPasswordCallback(getAlias(), WSPasswordCallback.DECRYPT);
                Utils.doCallback(getCallbackHandler(), pwCb);
                Key key = getCrypto().getPrivateKey(getAlias(), pwCb.getPassword());
                return key;
            } catch (Exception e) {
                throw new WSSecurityException(e);
            }
        }

        public PublicKey getPublicKey() throws WSSecurityException {
            try {
                X509Certificate x509Certificate = getX509Certificate();
                if (x509Certificate == null) {
                    return null;
                }
                return x509Certificate.getPublicKey();
            } catch (org.swssf.crypto.WSSecurityException e) {
                throw new WSSecurityException(e);
            }
        }

        public void verify() throws WSSecurityException {
            //todo verify certificate chain??
            try {
                X509Certificate x509Certificate = getX509Certificate();
                if (x509Certificate != null) {
                    x509Certificate.checkValidity();
                }

                verifyTrust(x509Certificate);

            } catch (org.swssf.crypto.WSSecurityException e) {
                throw new WSSecurityException(e);
            } catch (CertificateExpiredException e) {
                throw new WSSecurityException(e);
            } catch (CertificateNotYetValidException e) {
                throw new WSSecurityException(e);
            }
        }

        private void verifyTrust(X509Certificate x509Certificate) throws WSSecurityException {

            Set<TrustAnchor> trustedCerts = new HashSet<TrustAnchor>();

            try {
                if (cacerts != null) {
                    Enumeration<String> aliases = cacerts.aliases();
                    while (aliases.hasMoreElements()) {
                        String alias = aliases.nextElement();
                        X509Certificate x509Cert = (X509Certificate) cacerts.getCertificate(alias);
                        TrustAnchor trustAnchor = new TrustAnchor(x509Cert, null);
                        trustedCerts.add(trustAnchor);
                    }
                }

                if (getCrypto().getKeyStore() != null) {
                    Enumeration<String> aliases = getCrypto().getKeyStore().aliases();
                    while (aliases.hasMoreElements()) {
                        String alias = aliases.nextElement();
                        X509Certificate x509Cert = (X509Certificate) getCrypto().getKeyStore().getCertificate(alias);
                        TrustAnchor trustAnchor = new TrustAnchor(x509Cert, null);
                        trustedCerts.add(trustAnchor);
                    }
                }

                X509CertSelector x509CertSelector = new X509CertSelector();
                x509CertSelector.setCertificate(x509Certificate);

                PKIXBuilderParameters pkixBuilderParameters = new PKIXBuilderParameters(trustedCerts, x509CertSelector);
                pkixBuilderParameters.setRevocationEnabled(false);
                //todo provider?:
                CertStore intermediateCertStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(trustedCerts));
                pkixBuilderParameters.addCertStore(intermediateCertStore);

                //todo provider?:
                CertPathBuilder certPathBuilder = null;
                certPathBuilder = CertPathBuilder.getInstance("PKIX");
                PKIXCertPathValidatorResult pkixCertPathValidatorResult = (PKIXCertPathValidatorResult) certPathBuilder.build(pkixBuilderParameters);

            } catch (NoSuchAlgorithmException e) {
                throw new WSSecurityException(e);
            } catch (CertPathBuilderException e) {
                throw new WSSecurityException(e);
            } catch (InvalidAlgorithmParameterException e) {
                throw new WSSecurityException(e);
            } catch (KeyStoreException e) {
                throw new WSSecurityException(e);
            }
        }

        public SecurityToken getKeyWrappingToken() {
            return null;
        }

        public String getKeyWrappingTokenAlgorithm() {
            return null;
        }

        //todo return whole certpath for validation??

        public X509Certificate getX509Certificate() throws org.swssf.crypto.WSSecurityException {
            if (this.x509Certificate == null) {
                X509Certificate[] x509Certificates = getCrypto().getCertificates(getAlias());
                if (x509Certificates.length == 0) {
                    return null;
                }
                this.x509Certificate = x509Certificates[0];
            }
            return this.x509Certificate;
        }

        protected abstract String getAlias() throws org.swssf.crypto.WSSecurityException;
    }

    class ThumbprintSHA1SecurityToken extends X509SecurityToken {
        private String alias = null;
        private byte[] binaryContent;

        ThumbprintSHA1SecurityToken(Crypto crypto, CallbackHandler callbackHandler, byte[] binaryContent) {
            super(crypto, callbackHandler);
            this.binaryContent = binaryContent;
        }

        protected String getAlias() throws org.swssf.crypto.WSSecurityException {
            if (this.alias == null) {
                this.alias = getCrypto().getAliasForX509CertThumb(binaryContent);
            }
            return this.alias;
        }

        public Constants.KeyIdentifierType getKeyIdentifierType() {
            return Constants.KeyIdentifierType.THUMBPRINT_IDENTIFIER;
        }
    }

    class X509SubjectKeyIdentifierSecurityToken extends X509SecurityToken {
        private String alias = null;
        private byte[] binaryContent;

        X509SubjectKeyIdentifierSecurityToken(Crypto crypto, CallbackHandler callbackHandler, byte[] binaryContent) {
            super(crypto, callbackHandler);
            this.binaryContent = binaryContent;
        }

        protected String getAlias() throws org.swssf.crypto.WSSecurityException {
            if (this.alias == null) {
                this.alias = getCrypto().getAliasForX509Cert(binaryContent);
            }
            return this.alias;
        }

        public Constants.KeyIdentifierType getKeyIdentifierType() {
            return Constants.KeyIdentifierType.SKI_KEY_IDENTIFIER;
        }
    }

    class X509_V3SecurityToken extends X509SecurityToken {
        private String alias = null;
        private X509Certificate x509Certificate;

        X509_V3SecurityToken(Crypto crypto, CallbackHandler callbackHandler, byte[] binaryContent) throws WSSecurityException {
            super(crypto, callbackHandler);
            try {
                this.x509Certificate = getCrypto().loadCertificate(new ByteArrayInputStream(binaryContent));
            } catch (org.swssf.crypto.WSSecurityException e) {
                throw new WSSecurityException(e);
            }
        }

        protected String getAlias() throws org.swssf.crypto.WSSecurityException {
            if (this.alias == null) {
                this.alias = getCrypto().getAliasForX509Cert(this.x509Certificate);
            }
            return this.alias;
        }

        @Override
        public X509Certificate getX509Certificate() throws org.swssf.crypto.WSSecurityException {
            return this.x509Certificate;
        }

        public Constants.KeyIdentifierType getKeyIdentifierType() {
            return Constants.KeyIdentifierType.BST_EMBEDDED;
        }
    }

    class X509PKIPathv1SecurityToken extends X509SecurityToken {
        private String alias = null;
        private X509Certificate x509Certificate;

        X509PKIPathv1SecurityToken(Crypto crypto, CallbackHandler callbackHandler, byte[] binaryContent) throws WSSecurityException {
            super(crypto, callbackHandler);
            try {
                X509Certificate[] x509Certificates = crypto.getX509Certificates(binaryContent, false);
                if (x509Certificates != null && x509Certificates.length > 0) {
                    this.x509Certificate = x509Certificates[0];
                }
            } catch (org.swssf.crypto.WSSecurityException e) {
                throw new WSSecurityException(e);
            }
        }

        protected String getAlias() throws org.swssf.crypto.WSSecurityException {
            if (this.alias == null) {
                this.alias = getCrypto().getAliasForX509Cert(this.x509Certificate);
            }
            return this.alias;
        }

        @Override
        public X509Certificate getX509Certificate() throws org.swssf.crypto.WSSecurityException {
            return this.x509Certificate;
        }

        public Constants.KeyIdentifierType getKeyIdentifierType() {
            return Constants.KeyIdentifierType.BST_EMBEDDED;
        }
    }

    class X509DataSecurityToken extends X509SecurityToken {
        private String alias = null;
        protected X509DataType x509DataType;

        X509DataSecurityToken(Crypto crypto, CallbackHandler callbackHandler, X509DataType x509DataType) {
            super(crypto, callbackHandler);
            this.x509DataType = x509DataType;
        }

        protected String getAlias() throws org.swssf.crypto.WSSecurityException {
            if (this.alias == null) {
                this.alias = getCrypto().getAliasForX509Cert(x509DataType.getX509IssuerSerialType().getX509IssuerName(), x509DataType.getX509IssuerSerialType().getX509SerialNumber());
            }
            return this.alias;
        }

        public Constants.KeyIdentifierType getKeyIdentifierType() {
            return Constants.KeyIdentifierType.ISSUER_SERIAL;
        }
    }
}
