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
package org.swssf.impl.securityToken;

import org.apache.commons.codec.binary.Base64;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.BinarySecurityTokenType;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.KeyIdentifierType;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.SecurityTokenReferenceType;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.UsernameTokenType;
import org.swssf.crypto.Crypto;
import org.swssf.ext.*;
import org.w3._2000._09.xmldsig_.KeyInfoType;

import javax.security.auth.callback.CallbackHandler;

/**
 * Factory to create SecurityToken Objects from keys in XML
 *
 * @author $Author: giger $
 * @version $Revision: 281 $ $Date: 2011-01-04 21:15:27 +0100 (Tue, 04 Jan 2011) $
 */
public class
        SecurityTokenFactory {

    private SecurityTokenFactory() {
    }

    public synchronized static SecurityTokenFactory newInstance() throws WSSecurityException {
        return new SecurityTokenFactory();
    }

    public SecurityToken getSecurityToken(KeyInfoType keyInfoType, Crypto crypto, final CallbackHandler callbackHandler, SecurityContext securityContext) throws WSSecurityException {
        try {
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

                        //prevent recursive key reference DOS:
                        Integer invokeCount = securityContext.<Integer>get("" + Thread.currentThread().hashCode());
                        if (invokeCount == null) {
                            invokeCount = 0;
                        }
                        invokeCount++;
                        if (invokeCount == 10) {
                            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY_TOKEN);
                        }
                        securityContext.put("" + Thread.currentThread().hashCode(), invokeCount);

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
        } finally {
            securityContext.remove("" + Thread.currentThread().hashCode());
        }
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

}
