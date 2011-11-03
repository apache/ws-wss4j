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
package org.swssf.wss.impl.securityToken;

import org.apache.commons.codec.binary.Base64;
import org.opensaml.common.SAMLVersion;
import org.swssf.binding.wss10.*;
import org.swssf.binding.xmldsig.KeyInfoType;
import org.swssf.binding.xmldsig.X509DataType;
import org.swssf.wss.ext.WSSConstants;
import org.swssf.wss.ext.WSSUtils;
import org.swssf.wss.ext.WSSecurityException;
import org.swssf.wss.impl.saml.SAMLKeyInfo;
import org.swssf.xmlsec.crypto.Crypto;
import org.swssf.xmlsec.ext.*;
import org.swssf.xmlsec.impl.securityToken.SecurityTokenFactory;

import javax.security.auth.callback.CallbackHandler;
import javax.xml.stream.events.XMLEvent;
import java.util.Deque;

/**
 * Factory to create SecurityToken Objects from keys in XML
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SecurityTokenFactoryImpl extends SecurityTokenFactory {

    public SecurityTokenFactoryImpl() {
    }

    @Override
    public SecurityToken getSecurityToken(KeyInfoType keyInfoType, Crypto crypto,
                                          final CallbackHandler callbackHandler, SecurityContext securityContext,
                                          Object processor) throws XMLSecurityException {
        if (keyInfoType != null) {
            final SecurityTokenReferenceType securityTokenReferenceType = XMLSecurityUtils.getQNameType(keyInfoType.getContent(), WSSConstants.TAG_wsse_SecurityTokenReference);
            return getSecurityToken(securityTokenReferenceType, crypto, callbackHandler, securityContext, processor);
        } else if (crypto.getDefaultX509Alias() != null) {
            return new X509DefaultSecurityToken(securityContext, crypto, callbackHandler, crypto.getDefaultX509Alias(), crypto.getDefaultX509Alias(), processor);
        }
        throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, "noKeyinfo");
    }

    public static SecurityToken getSecurityToken(SecurityTokenReferenceType securityTokenReferenceType, Crypto crypto,
                                                 final CallbackHandler callbackHandler, SecurityContext securityContext,
                                                 Object processor) throws XMLSecurityException {
        try {
            if (securityTokenReferenceType == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, "noSecTokRef");
            }

            final X509DataType x509DataType = XMLSecurityUtils.getQNameType(securityTokenReferenceType.getAny(), WSSConstants.TAG_dsig_X509Data);
            final KeyIdentifierType keyIdentifierType = XMLSecurityUtils.getQNameType(securityTokenReferenceType.getAny(), WSSConstants.TAG_wsse_KeyIdentifier);
            final ReferenceType referenceType = XMLSecurityUtils.getQNameType(securityTokenReferenceType.getAny(), WSSConstants.TAG_wsse_Reference);
            if (x509DataType != null) {
                return new DelegatingSecurityToken(WSSConstants.KeyIdentifierType.ISSUER_SERIAL,
                        new X509DataSecurityToken(securityContext, crypto, callbackHandler,
                                x509DataType,
                                securityTokenReferenceType.getId(), processor));
            }
            //todo this is not supported by outputProcessor but can be implemented.
            // We'll have a look at the spec if this is allowed
            else if (keyIdentifierType != null) {
                String valueType = keyIdentifierType.getValueType();
                String encodingType = keyIdentifierType.getEncodingType();

                byte[] binaryContent = null;
                if (WSSConstants.SOAPMESSAGE_NS10_BASE64_ENCODING.equals(encodingType)) {
                    binaryContent = Base64.decodeBase64(keyIdentifierType.getValue());
                }

                if (WSSConstants.NS_X509_V3_TYPE.equals(valueType)) {
                    return new X509_V3SecurityToken(securityContext, crypto, callbackHandler, binaryContent, securityTokenReferenceType.getId(), processor);
                } else if (WSSConstants.NS_X509SubjectKeyIdentifier.equals(valueType)) {
                    return new X509SubjectKeyIdentifierSecurityToken(securityContext, crypto, callbackHandler, binaryContent, securityTokenReferenceType.getId(), processor);
                } else if (WSSConstants.NS_THUMBPRINT.equals(valueType)) {
                    return new ThumbprintSHA1SecurityToken(securityContext, crypto, callbackHandler, binaryContent, securityTokenReferenceType.getId(), processor);
                } else if (WSSConstants.NS_SAML10_TYPE.equals(valueType) || WSSConstants.NS_SAML20_TYPE.equals(valueType)) {
                    SecurityTokenProvider securityTokenProvider = securityContext.getSecurityTokenProvider(keyIdentifierType.getValue());
                    if (securityTokenProvider == null) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.SECURITY_TOKEN_UNAVAILABLE, "noToken", keyIdentifierType.getValue());
                    }
                    return securityTokenProvider.getSecurityToken(crypto);
                }
            } else if (referenceType != null) {

                String uri = referenceType.getURI();
                if (uri == null) {
                    throw new WSSecurityException("badReferenceURI");
                }
                uri = WSSUtils.dropReferenceMarker(uri);
                //referenced BST:*/
                //we have to search BST somewhere in the doc. First we will check for a BST already processed and
                //stored in the context. Otherwise we will abort now.

                //prevent recursive key reference DOS:
                Integer invokeCount = securityContext.<Integer>get("" + Thread.currentThread().hashCode());
                if (invokeCount == null) {
                    invokeCount = 0;
                }
                invokeCount++;
                if (invokeCount == 10) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN);
                }
                securityContext.put("" + Thread.currentThread().hashCode(), invokeCount);

                SecurityTokenProvider securityTokenProvider = securityContext.getSecurityTokenProvider(uri);
                if (securityTokenProvider == null) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.SECURITY_TOKEN_UNAVAILABLE, "noToken", uri);
                }
                return new DelegatingSecurityToken(WSSConstants.KeyIdentifierType.SECURITY_TOKEN_DIRECT_REFERENCE, securityTokenProvider.getSecurityToken(crypto));
            }
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, "noKeyinfo");
        } finally {
            securityContext.remove("" + Thread.currentThread().hashCode());
        }
    }

    public static SecurityToken getSecurityToken(BinarySecurityTokenType binarySecurityTokenType, SecurityContext securityContext, Crypto crypto, CallbackHandler callbackHandler, Object processor) throws XMLSecurityException {

        //only Base64Encoding is supported
        if (!WSSConstants.SOAPMESSAGE_NS10_BASE64_ENCODING.equals(binarySecurityTokenType.getEncodingType())) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, "badEncoding", binarySecurityTokenType.getEncodingType());
        }

        byte[] securityTokenData = Base64.decodeBase64(binarySecurityTokenType.getValue());

        if (WSSConstants.NS_X509_V3_TYPE.equals(binarySecurityTokenType.getValueType())) {
            return new X509_V3SecurityToken(securityContext, crypto, callbackHandler, securityTokenData, binarySecurityTokenType.getId(), processor);
        } else if (WSSConstants.NS_X509PKIPathv1.equals(binarySecurityTokenType.getValueType())) {
            return new X509PKIPathv1SecurityToken(securityContext, crypto, callbackHandler, securityTokenData, binarySecurityTokenType.getId(), processor);
        } else {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, "invalidValueType", binarySecurityTokenType.getValueType());
        }
    }

    public static SecurityToken getSecurityToken(String username, String password, String created, byte[] nonce,
                                                 byte[] salt, Long iteration, SecurityContext securityContext,
                                                 String id, Object processor) throws WSSecurityException {
        return new UsernameSecurityToken(username, password, created, nonce, salt, iteration, securityContext, id, processor);
    }

    public static SecurityToken getSecurityToken(SAMLVersion samlVersion, SAMLKeyInfo samlKeyInfo, SecurityContext securityContext, Crypto crypto, CallbackHandler callbackHandler, String id, Object processor) throws WSSecurityException {
        return new SAMLSecurityToken(samlVersion, samlKeyInfo, securityContext, crypto, callbackHandler, id, processor);
    }

    public static SecurityToken getSecurityToken(String referencedTokenId, Deque<XMLEvent> xmlEvents, Crypto crypto, CallbackHandler callbackHandler, SecurityContext securityContext, String id, Object processor) throws XMLSecurityException {
        return new SecurityTokenReference(securityContext.getSecurityTokenProvider(referencedTokenId).getSecurityToken(crypto), xmlEvents, crypto, callbackHandler, id, processor);
    }
}
