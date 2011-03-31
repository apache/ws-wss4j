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
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.UsernameTokenType;
import org.swssf.config.JCEAlgorithmMapper;
import org.swssf.crypto.Crypto;
import org.swssf.ext.*;
import org.w3._2000._09.xmldsig_.KeyInfoType;
import org.w3._2000._09.xmldsig_.X509DataType;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.callback.CallbackHandler;
import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Hashtable;
import java.util.Map;

/**
 * Factory to create SecurityToken Objects from keys in XML
 *
 * @author $Author: giger $
 * @version $Revision: 281 $ $Date: 2011-01-04 21:15:27 +0100 (Tue, 04 Jan 2011) $
 */
public class SecurityTokenFactory {

    private SecurityTokenFactory() {
    }

    public synchronized static SecurityTokenFactory newInstance() throws WSSecurityException {
        return new SecurityTokenFactory();
    }

    public SecurityToken getSecurityToken(KeyInfoType keyInfoType, Crypto crypto, final CallbackHandler callbackHandler, SecurityContext securityContext) throws WSSecurityException {
        if (keyInfoType != null) {
            final SecurityTokenReferenceType securityTokenReferenceType = keyInfoType.getSecurityTokenReferenceType();
            if (securityTokenReferenceType == null) {
                throw new WSSecurityException(WSSecurityException.INVALID_SECURITY, "noSecTokRef");
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
                    binaryContent = Base64.decodeBase64(keyIdentifierType.getValue());
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
                    //we have to search BST somewhere in the doc. First we will check for a BST already processed and
                    //stored in the context. Otherwise we will abort now.
                    SecurityTokenProvider securityTokenProvider = securityContext.getSecurityTokenProvider(uri);
                    if (securityTokenProvider == null) {
                        throw new WSSecurityException(WSSecurityException.SECURITY_TOKEN_UNAVAILABLE, "noToken", new Object[]{uri});
                    }
                    return securityTokenProvider.getSecurityToken(crypto);
                }
            }
        } else if (crypto.getDefaultX509Alias() != null) {
            return new X509DefaultSecurityToken(crypto, callbackHandler, crypto.getDefaultX509Alias());
        }
        throw new WSSecurityException(WSSecurityException.INVALID_SECURITY, "noKeyinfo");
    }

    public SecurityToken getSecurityToken(BinarySecurityTokenType binarySecurityTokenType, Crypto crypto, CallbackHandler callbackHandler) throws WSSecurityException {

        //only Base64Encoding is supported
        if (!Constants.SOAPMESSAGE_NS10_BASE64_ENCODING.equals(binarySecurityTokenType.getEncodingType())) {
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY_TOKEN, "badEncoding", new Object[]{binarySecurityTokenType.getEncodingType()});
        }

        byte[] securityTokenData = Base64.decodeBase64(binarySecurityTokenType.getValue());

        if (Constants.NS_X509_V3_TYPE.equals(binarySecurityTokenType.getValueType())) {
            return new X509_V3SecurityToken(crypto, callbackHandler, securityTokenData);
        } else if (Constants.NS_X509PKIPathv1.equals(binarySecurityTokenType.getValueType())) {
            return new X509PKIPathv1SecurityToken(crypto, callbackHandler, securityTokenData);
        } else {
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY_TOKEN, "invalidValueType", new Object[]{binarySecurityTokenType.getValueType()});
        }
    }

    public SecurityToken getSecurityToken(UsernameTokenType usernameTokenType) throws WSSecurityException {
            return new UsernameSecurityToken(usernameTokenType);
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

    public class UsernameSecurityToken implements SecurityToken {

        private static final int DEFAULT_ITERATION = 1000;

        private UsernameTokenType usernameTokenType;

        public UsernameSecurityToken(UsernameTokenType usernameTokenType) {
            this.usernameTokenType = usernameTokenType;
        }

        private String getCreated() {
            return usernameTokenType.getCreated();
        }

        private String getNonce() {
            return usernameTokenType.getNonce();
        }

        private byte[] getSalt() {
            return Base64.decodeBase64(usernameTokenType.getSalt());
        }

        private Integer getIteration() {
            return Integer.parseInt(usernameTokenType.getIteration());
        }

        /**
         * This method generates a derived key as defined in WSS Username
         * Token Profile.
         *
         * @param password  The password to include in the key generation
         * @param salt      The Salt value
         * @param iteration The Iteration value. If zero (0) is given the method uses the
         *                  default value
         * @return Returns the derived key a byte array
         * @throws WSSecurityException
         */
        public byte[] generateDerivedKey(String rawPassword, byte[] salt, int iteration) throws WSSecurityException {
            if (iteration == 0) {
                iteration = DEFAULT_ITERATION;
            }
            byte[] pwBytes = null;
            try {
                pwBytes = rawPassword.getBytes("UTF-8");
            } catch (final java.io.UnsupportedEncodingException e) {
                throw new WSSecurityException(WSSecurityException.FAILURE, null, e);
            }

            byte[] pwSalt = new byte[salt.length + pwBytes.length];
            System.arraycopy(pwBytes, 0, pwSalt, 0, pwBytes.length);
            System.arraycopy(salt, 0, pwSalt, pwBytes.length, salt.length);

            MessageDigest sha = null;
            try {
                sha = MessageDigest.getInstance("SHA-1");
            } catch (NoSuchAlgorithmException e) {
                throw new WSSecurityException(WSSecurityException.FAILURE, "noSHA1availabe", null, e);
            }
            sha.reset();

            // Make the first hash round with start value
            byte[] k = sha.digest(pwSalt);

            // Perform the 1st up to iteration-1 hash rounds
            for (int i = 1; i < iteration; i++) {
                k = sha.digest(k);
            }
            return k;
        }

        /**
         * Gets the secret key as per WS-Trust spec.
         *
         * @param keylen      How many bytes to generate for the key
         * @param labelString the label used to generate the seed
         * @return a secret key constructed from information contained in this
         *         username token
         */
        private byte[] getSecretKey(String rawPassword, int keylen, String labelString) throws WSSecurityException {
            byte[] key = null;
            try {
                Mac mac = Mac.getInstance("HMACSHA1");
                byte[] password = rawPassword.getBytes("UTF-8");
                byte[] label = labelString.getBytes("UTF-8");
                byte[] nonce = Base64.decodeBase64(getNonce());
                byte[] created = getCreated().getBytes("UTF-8");
                byte[] seed = new byte[label.length + nonce.length + created.length];

                int offset = 0;
                System.arraycopy(label, 0, seed, offset, label.length);
                offset += label.length;

                System.arraycopy(nonce, 0, seed, offset, nonce.length);
                offset += nonce.length;

                System.arraycopy(created, 0, seed, offset, created.length);

                key = P_hash(password, seed, mac, keylen);

            } catch (NoSuchAlgorithmException e) {
                throw new WSSecurityException(WSSecurityException.FAILURE, "noHMACSHA1available", null, e);
            } catch (UnsupportedEncodingException e) {
                throw new WSSecurityException(WSSecurityException.FAILURE, null, e);
            }
            return key;
        }

        /**
         * P_hash as defined in RFC 2246 for TLS.
         *
         * @param secret   is the key for the HMAC
         * @param seed     the seed value to start the generation - A(0)
         * @param mac      the HMAC algorithm
         * @param required number of bytes to generate
         * @return a byte array that contains a secret key
         * @throws Exception
         */
        private byte[] P_hash(byte[] secret, byte[] seed, Mac mac, int required) throws WSSecurityException {
            byte[] out = new byte[required];
            int offset = 0;
            int toCopy;
            byte[] a, tmp;

            try {
                // a(0) is the seed
                a = seed;
                SecretKeySpec key = new SecretKeySpec(secret, "HMACSHA1");
                mac.init(key);
                while (required > 0) {
                    mac.update(a);
                    a = mac.doFinal();
                    mac.update(a);
                    mac.update(seed);
                    tmp = mac.doFinal();
                    toCopy = Math.min(required, tmp.length);
                    System.arraycopy(tmp, 0, out, offset, toCopy);
                    offset += toCopy;
                    required -= toCopy;
                }
            } catch (InvalidKeyException e) {
                throw new WSSecurityException(WSSecurityException.FAILURE, null, e);
            }
            return out;
        }

        public boolean isAsymmetric() {
            return false;
        }

        private Map<String, Key> keyTable = new Hashtable<String, Key>();

        public Key getSecretKey(String algorithmURI) throws WSSecurityException {
            byte[] secretToken = null;
            if (usernameTokenType.getSalt() != null && usernameTokenType.getIteration() != null) {
                int iteration = getIteration();
                byte[] salt = getSalt();
                secretToken = generateDerivedKey(usernameTokenType.getPassword(), salt, iteration);
            } else {
                secretToken = getSecretKey(usernameTokenType.getPassword(), Constants.WSE_DERIVED_KEY_LEN, Constants.LABEL_FOR_DERIVED_KEY);
            }

            if (keyTable.containsKey(algorithmURI)) {
                return keyTable.get(algorithmURI);
            } else {
                String algoFamily = JCEAlgorithmMapper.getJCEKeyAlgorithmFromURI(algorithmURI);
                Key key = new SecretKeySpec(secretToken, algoFamily);
                keyTable.put(algorithmURI, key);
                return key;
            }
        }

        public PublicKey getPublicKey() throws WSSecurityException {
            return null;
        }

        public void verify() throws WSSecurityException {
        }

        public SecurityToken getKeyWrappingToken() {
            return null;
        }

        public String getKeyWrappingTokenAlgorithm() {
            return null;
        }

        public Constants.KeyIdentifierType getKeyIdentifierType() {
            return null;
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
            WSPasswordCallback pwCb = new WSPasswordCallback(getAlias(), WSPasswordCallback.DECRYPT);
            Utils.doCallback(getCallbackHandler(), pwCb);
            return getCrypto().getPrivateKey(getAlias(), pwCb.getPassword());
        }

        public PublicKey getPublicKey() throws WSSecurityException {
            X509Certificate x509Certificate = getX509Certificate();
            if (x509Certificate == null) {
                return null;
            }
            return x509Certificate.getPublicKey();
        }

        //todo testing:
        public void verify() throws WSSecurityException {
            try {
                X509Certificate x509Certificate = getX509Certificate();
                if (x509Certificate != null) {
                    x509Certificate.checkValidity();
                }
                getCrypto().validateCert(x509Certificate);
            } catch (CertificateExpiredException e) {
                throw new WSSecurityException(WSSecurityException.FAILED_CHECK, null, e);
            } catch (CertificateNotYetValidException e) {
                throw new WSSecurityException(WSSecurityException.FAILED_CHECK, null, e);
            }
        }

        public SecurityToken getKeyWrappingToken() {
            return null;
        }

        public String getKeyWrappingTokenAlgorithm() {
            return null;
        }

        public X509Certificate getX509Certificate() throws WSSecurityException {
            if (this.x509Certificate == null) {
                X509Certificate[] x509Certificates = getCrypto().getCertificates(getAlias());
                if (x509Certificates.length == 0) {
                    return null;
                }
                this.x509Certificate = x509Certificates[0];
            }
            return this.x509Certificate;
        }

        protected abstract String getAlias() throws WSSecurityException;
    }

    class ThumbprintSHA1SecurityToken extends X509SecurityToken {
        private String alias = null;
        private byte[] binaryContent;

        ThumbprintSHA1SecurityToken(Crypto crypto, CallbackHandler callbackHandler, byte[] binaryContent) {
            super(crypto, callbackHandler);
            this.binaryContent = binaryContent;
        }

        protected String getAlias() throws WSSecurityException {
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

        protected String getAlias() throws WSSecurityException {
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
            this.x509Certificate = getCrypto().loadCertificate(new ByteArrayInputStream(binaryContent));
        }

        protected String getAlias() throws WSSecurityException {
            if (this.alias == null) {
                this.alias = getCrypto().getAliasForX509Cert(this.x509Certificate);
            }
            return this.alias;
        }

        @Override
        public X509Certificate getX509Certificate() throws WSSecurityException {
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
            X509Certificate[] x509Certificates = crypto.getX509Certificates(binaryContent, false);
            if (x509Certificates != null && x509Certificates.length > 0) {
                this.x509Certificate = x509Certificates[0];
            }
        }

        protected String getAlias() throws WSSecurityException {
            if (this.alias == null) {
                this.alias = getCrypto().getAliasForX509Cert(this.x509Certificate);
            }
            return this.alias;
        }

        @Override
        public X509Certificate getX509Certificate() throws WSSecurityException {
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

        protected String getAlias() throws WSSecurityException {
            if (this.alias == null) {
                this.alias = getCrypto().getAliasForX509Cert(x509DataType.getX509IssuerSerialType().getX509IssuerName(), x509DataType.getX509IssuerSerialType().getX509SerialNumber());
            }
            return this.alias;
        }

        public Constants.KeyIdentifierType getKeyIdentifierType() {
            return Constants.KeyIdentifierType.ISSUER_SERIAL;
        }
    }

    class X509DefaultSecurityToken extends X509SecurityToken {
        private String alias = null;

        X509DefaultSecurityToken(Crypto crypto, CallbackHandler callbackHandler, String alias) {
            super(crypto, callbackHandler);
            this.alias = alias;
        }

        protected String getAlias() throws WSSecurityException {
            return this.alias;
        }

        public Constants.KeyIdentifierType getKeyIdentifierType() {
            return Constants.KeyIdentifierType.NO_TOKEN;
        }
    }
}
