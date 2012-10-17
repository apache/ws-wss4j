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
package org.apache.ws.security.stax.impl.securityToken;

import org.apache.commons.codec.binary.Base64;
import org.apache.ws.security.binding.wss10.KeyIdentifierType;
import org.apache.ws.security.binding.wss10.SecurityTokenReferenceType;
import org.apache.ws.security.common.bsp.BSPRule;
import org.apache.ws.security.common.crypto.Crypto;
import org.apache.ws.security.common.ext.WSSecurityException;
import org.apache.ws.security.stax.ext.WSSConstants;
import org.apache.ws.security.stax.ext.WSSSecurityProperties;
import org.apache.ws.security.stax.ext.WSSUtils;
import org.apache.ws.security.stax.ext.WSSecurityContext;
import org.apache.xml.security.binding.xmldsig.*;
import org.apache.xml.security.binding.xmldsig11.ECKeyValueType;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.*;
import org.apache.xml.security.stax.impl.securityToken.DsaKeyValueSecurityToken;
import org.apache.xml.security.stax.impl.securityToken.ECKeyValueSecurityToken;
import org.apache.xml.security.stax.impl.securityToken.RsaKeyValueSecurityToken;
import org.apache.xml.security.stax.impl.securityToken.SecurityTokenFactory;
import org.opensaml.common.SAMLVersion;

import javax.security.auth.callback.CallbackHandler;

/**
 * Factory to create SecurityToken Objects from keys in XML
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SecurityTokenFactoryImpl extends SecurityTokenFactory {

    public SecurityTokenFactoryImpl() {
    }

    public SecurityToken getSecurityToken(KeyInfoType keyInfoType, SecurityToken.KeyInfoUsage keyInfoUsage,
                                          XMLSecurityProperties securityProperties, SecurityContext securityContext)
            throws XMLSecurityException {

        Crypto crypto = null;
        if (keyInfoUsage == SecurityToken.KeyInfoUsage.SIGNATURE_VERIFICATION) {
            crypto = ((WSSSecurityProperties) securityProperties).getSignatureVerificationCrypto();
        } else if (keyInfoUsage == SecurityToken.KeyInfoUsage.DECRYPTION) {
            crypto = ((WSSSecurityProperties) securityProperties).getDecryptionCrypto();
        }

        if (keyInfoType != null) {
            final SecurityTokenReferenceType securityTokenReferenceType
                    = XMLSecurityUtils.getQNameType(keyInfoType.getContent(), WSSConstants.TAG_wsse_SecurityTokenReference);
            if (securityTokenReferenceType != null) {
                return getSecurityToken(securityTokenReferenceType, crypto, securityProperties.getCallbackHandler(), securityContext);
            }
            final KeyValueType keyValueType
                    = XMLSecurityUtils.getQNameType(keyInfoType.getContent(), WSSConstants.TAG_dsig_KeyValue);
            if (keyValueType != null) {
                return getSecurityToken(keyValueType, crypto, securityProperties.getCallbackHandler(), securityContext);
            }

        } else if (crypto.getDefaultX509Identifier() != null) {
            return new X509DefaultSecurityToken(
                    (WSSecurityContext) securityContext, crypto, securityProperties.getCallbackHandler(), crypto.getDefaultX509Identifier(),
                    crypto.getDefaultX509Identifier(), null
            );
        }
        throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, "noKeyinfo");
    }

    public static SecurityToken getSecurityToken(SecurityTokenReferenceType securityTokenReferenceType, Crypto crypto,
                                                 final CallbackHandler callbackHandler, SecurityContext securityContext)
            throws XMLSecurityException {

        //BSP.R5205 is a joke. In real life we have a lot of cases which prevents a one pass processing.
        //Say encrypted Tokens, SignedTokens, Signed-Timestamp first...

        try {
            if (securityTokenReferenceType == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, "noSecTokRef");
            }

            if (securityTokenReferenceType.getAny().size() > 1) {
                ((WSSecurityContext) securityContext).handleBSPRule(BSPRule.R3061);
            }
            
            //todo BSP.R3027 KeyName? not supported ATM
            //todo BSP.R3060,BSP.R3025,BSP.R3056 only one Embedded element? Not supported ATM
            final X509DataType x509DataType
                    = XMLSecurityUtils.getQNameType(securityTokenReferenceType.getAny(), WSSConstants.TAG_dsig_X509Data);
            if (x509DataType != null) {
                return new X509DataSecurityToken((WSSecurityContext) securityContext, crypto, callbackHandler,
                        x509DataType, securityTokenReferenceType.getId(),
                        WSSConstants.WSSKeyIdentifierType.ISSUER_SERIAL);
            }
            
            String tokenType = 
                    XMLSecurityUtils.getQNameAttribute(
                        securityTokenReferenceType.getOtherAttributes(), 
                        WSSConstants.ATT_wsse11_TokenType);

            final KeyIdentifierType keyIdentifierType
                    = XMLSecurityUtils.getQNameType(securityTokenReferenceType.getAny(), WSSConstants.TAG_wsse_KeyIdentifier);
            if (keyIdentifierType != null) {
                String valueType = keyIdentifierType.getValueType();
                if (valueType == null) {
                    ((WSSecurityContext) securityContext).handleBSPRule(BSPRule.R3054);
                }
                String encodingType = keyIdentifierType.getEncodingType();

                byte[] binaryContent = null;
                if (WSSConstants.SOAPMESSAGE_NS10_BASE64_ENCODING.equals(encodingType)) {
                    binaryContent = Base64.decodeBase64(keyIdentifierType.getValue());
                } else if (!WSSConstants.NS_SAML10_TYPE.equals(valueType) && !WSSConstants.NS_SAML20_TYPE.equals(valueType)) {
                    if (encodingType == null) {
                        ((WSSecurityContext) securityContext).handleBSPRule(BSPRule.R3070);
                    } else {
                        ((WSSecurityContext) securityContext).handleBSPRule(BSPRule.R3071);
                    }
                } else if (encodingType != null 
                        && (WSSConstants.NS_SAML10_TYPE.equals(valueType) || WSSConstants.NS_SAML20_TYPE.equals(valueType))) {
                    ((WSSecurityContext) securityContext).handleBSPRule(BSPRule.R6604);
                }

                if (WSSConstants.NS_X509_V3_TYPE.equals(valueType)) {
                    return new X509_V3SecurityToken(
                            (WSSecurityContext) securityContext, crypto, callbackHandler,
                            binaryContent, securityTokenReferenceType.getId(), WSSConstants.WSSKeyIdentifierType.X509_KEY_IDENTIFIER);
                } else if (WSSConstants.NS_X509SubjectKeyIdentifier.equals(valueType)) {
                    return new X509SubjectKeyIdentifierSecurityToken(
                            (WSSecurityContext) securityContext, crypto, callbackHandler, binaryContent,
                            securityTokenReferenceType.getId(), WSSConstants.WSSKeyIdentifierType.SKI_KEY_IDENTIFIER);
                } else if (WSSConstants.NS_THUMBPRINT.equals(valueType)) {
                    return new ThumbprintSHA1SecurityToken(
                            (WSSecurityContext) securityContext, crypto, callbackHandler, binaryContent,
                            securityTokenReferenceType.getId(), WSSConstants.WSSKeyIdentifierType.THUMBPRINT_IDENTIFIER);
                } else if (WSSConstants.NS_SAML10_TYPE.equals(valueType) || WSSConstants.NS_SAML20_TYPE.equals(valueType)) {
                    if (WSSConstants.NS_SAML20_TYPE.equals(valueType) && !WSSConstants.NS_SAML20_TOKEN_PROFILE_TYPE.equals(tokenType)) {
                        ((WSSecurityContext) securityContext).handleBSPRule(BSPRule.R6617);
                    } else if (WSSConstants.NS_SAML10_TYPE.equals(valueType) && !WSSConstants.NS_SAML11_TOKEN_PROFILE_TYPE.equals(tokenType)) {
                        ((WSSecurityContext) securityContext).handleBSPRule(BSPRule.R6611);
                    }
                    SecurityTokenProvider securityTokenProvider = securityContext.getSecurityTokenProvider(keyIdentifierType.getValue());
                    if (securityTokenProvider == null) {
                        throw new WSSecurityException(
                                WSSecurityException.ErrorCode.SECURITY_TOKEN_UNAVAILABLE, "noToken", keyIdentifierType.getValue());
                    }
                    return securityTokenProvider.getSecurityToken();
                } else {
                    //we do enforce BSP compliance here but will fail anyway since we cannot identify the referenced token
                    ((WSSecurityContext) securityContext).handleBSPRule(BSPRule.R3063);
                }
            }

            final org.apache.ws.security.binding.wss10.ReferenceType referenceType
                    = XMLSecurityUtils.getQNameType(securityTokenReferenceType.getAny(), WSSConstants.TAG_wsse_Reference);
            if (referenceType != null) {
                //We do not check for BSP.R3023, BSP.R3022, BSP.R3066, BSP.R3067, BSP.R3024, BSP.R3064, BSP.R3211, BSP.R3059

                String uri = referenceType.getURI();
                if (uri == null) {
                    //we do enforce BSP compliance here but will fail anyway since we cannot identify the referenced token
                    ((WSSecurityContext) securityContext).handleBSPRule(BSPRule.R3062);
                    throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, "badReferenceURI");
                }
                if (!uri.startsWith("#")) {
                    ((WSSecurityContext) securityContext).handleBSPRule(BSPRule.R5204);
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
                if (securityTokenProvider.getSecurityToken() instanceof SecurityTokenReference) {
                    ((WSSecurityContext) securityContext).handleBSPRule(BSPRule.R3057);
                } else if (securityTokenProvider.getSecurityToken() instanceof X509PKIPathv1SecurityToken) {
                    String valueType = referenceType.getValueType();
                    if (!WSSConstants.NS_X509PKIPathv1.equals(valueType)) {
                        ((WSSecurityContext) securityContext).handleBSPRule(BSPRule.R3058);
                    }
                    if (!WSSConstants.NS_X509PKIPathv1.equals(tokenType)) {
                        ((WSSecurityContext) securityContext).handleBSPRule(BSPRule.R5215);
                    }
                } else if (securityTokenProvider.getSecurityToken() instanceof X509SecurityToken) {
                    String valueType = referenceType.getValueType();
                    if (!WSSConstants.NS_X509_V3_TYPE.equals(valueType)) {
                        ((WSSecurityContext) securityContext).handleBSPRule(BSPRule.R3058);
                    }
                } else if (securityTokenProvider.getSecurityToken() instanceof UsernameSecurityToken) {
                    String valueType = referenceType.getValueType();
                    if (!WSSConstants.NS_USERNAMETOKEN_PROFILE_UsernameToken.equals(valueType)) {
                        ((WSSecurityContext) securityContext).handleBSPRule(BSPRule.R4214);
                    }
                } else if (securityTokenProvider.getSecurityToken() instanceof SAMLSecurityToken) {
                    SAMLVersion samlVersion = 
                            ((SAMLSecurityToken)securityTokenProvider.getSecurityToken()).getSamlVersion();
                    if (samlVersion == SAMLVersion.VERSION_20) {
                        String valueType = referenceType.getValueType();
                        if (valueType != null && !"".equals(valueType)) {
                            ((WSSecurityContext) securityContext).handleBSPRule(BSPRule.R6614);
                        }
                        if (!WSSConstants.NS_SAML20_TOKEN_PROFILE_TYPE.equals(tokenType)) {
                            ((WSSecurityContext) securityContext).handleBSPRule(BSPRule.R6617);
                        }
                    } else if (samlVersion == SAMLVersion.VERSION_10 && !WSSConstants.NS_SAML11_TOKEN_PROFILE_TYPE.equals(tokenType)) {
                        ((WSSecurityContext) securityContext).handleBSPRule(BSPRule.R6611);
                    }
                } 
                
                
                return securityTokenProvider.getSecurityToken();
            }
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, "noKeyinfo");
        } finally {
            securityContext.remove("" + Thread.currentThread().hashCode());
        }
    }

    public static SecurityToken getSecurityToken(KeyValueType keyValueType, final Crypto crypto,
                                                 final CallbackHandler callbackHandler, SecurityContext securityContext)
            throws XMLSecurityException {

        final RSAKeyValueType rsaKeyValueType
                = XMLSecurityUtils.getQNameType(keyValueType.getContent(), WSSConstants.TAG_dsig_RSAKeyValue);
        if (rsaKeyValueType != null) {
            return new RsaKeyValueSecurityToken(rsaKeyValueType, (WSSecurityContext) securityContext,
                    WSSConstants.WSSKeyIdentifierType.KEY_VALUE) {
                @Override
                public void verify() throws XMLSecurityException {
                    crypto.verifyTrust(getPubKey("", null, null));
                }
            };
        }
        final DSAKeyValueType dsaKeyValueType
                = XMLSecurityUtils.getQNameType(keyValueType.getContent(), WSSConstants.TAG_dsig_DSAKeyValue);
        if (dsaKeyValueType != null) {
            return new DsaKeyValueSecurityToken(dsaKeyValueType, (WSSecurityContext) securityContext,
                    WSSConstants.WSSKeyIdentifierType.KEY_VALUE) {
                @Override
                public void verify() throws XMLSecurityException {
                    crypto.verifyTrust(getPubKey("", null, null));
                }
            };
        }
        final ECKeyValueType ecKeyValueType
                = XMLSecurityUtils.getQNameType(keyValueType.getContent(), WSSConstants.TAG_dsig11_ECKeyValue);
        if (ecKeyValueType != null) {
            return new ECKeyValueSecurityToken(ecKeyValueType, (WSSecurityContext) securityContext,
                    WSSConstants.WSSKeyIdentifierType.KEY_VALUE) {
                @Override
                public void verify() throws XMLSecurityException {
                    crypto.verifyTrust(getPubKey("", null, null));
                }
            };
        }
        throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, "unsupportedKeyInfo");
    }
}
