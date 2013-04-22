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
package org.apache.wss4j.stax.impl.securityToken;

import org.apache.commons.codec.binary.Base64;
import org.apache.wss4j.binding.wss10.KeyIdentifierType;
import org.apache.wss4j.binding.wss10.SecurityTokenReferenceType;
import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.ext.WSInboundSecurityContext;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.ext.WSSUtils;
import org.apache.wss4j.stax.securityToken.*;
import org.apache.xml.security.binding.xmldsig.*;
import org.apache.xml.security.binding.xmldsig11.ECKeyValueType;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.*;
import org.apache.xml.security.stax.securityToken.InboundSecurityToken;
import org.apache.xml.security.stax.securityToken.SecurityTokenFactory;
import org.apache.xml.security.stax.securityToken.SecurityTokenProvider;

import javax.security.auth.callback.CallbackHandler;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

/**
 * Factory to create InboundSecurityToken Objects from keys in XML
 */
public class SecurityTokenFactoryImpl extends SecurityTokenFactory {

    public SecurityTokenFactoryImpl() {
    }

    @Override
    public InboundSecurityToken getSecurityToken(KeyInfoType keyInfoType, WSSecurityTokenConstants.KeyUsage keyInfoUsage,
                                          XMLSecurityProperties securityProperties, InboundSecurityContext inboundSecurityContext)
            throws XMLSecurityException {

        Crypto crypto = null;
        if (WSSecurityTokenConstants.KeyUsage_Signature_Verification.equals(keyInfoUsage)) {
            crypto = ((WSSSecurityProperties) securityProperties).getSignatureVerificationCrypto();
        } else if (WSSecurityTokenConstants.KeyUsage_Decryption.equals(keyInfoUsage)) {
            crypto = ((WSSSecurityProperties) securityProperties).getDecryptionCrypto();
        }

        if (keyInfoType != null) {
            final SecurityTokenReferenceType securityTokenReferenceType
                    = XMLSecurityUtils.getQNameType(keyInfoType.getContent(), WSSConstants.TAG_wsse_SecurityTokenReference);
            if (securityTokenReferenceType != null) {
                return getSecurityToken(securityTokenReferenceType, crypto, ((WSSSecurityProperties)securityProperties).getCallbackHandler(), inboundSecurityContext,
                                        ((WSSSecurityProperties)securityProperties));
            }
            final KeyValueType keyValueType
                    = XMLSecurityUtils.getQNameType(keyInfoType.getContent(), WSSConstants.TAG_dsig_KeyValue);
            if (keyValueType != null) {
                return getSecurityToken(keyValueType, crypto, ((WSSSecurityProperties)securityProperties).getCallbackHandler(), inboundSecurityContext);
            }

        } else if (crypto.getDefaultX509Identifier() != null) {
            return new X509DefaultSecurityTokenImpl(
                    (WSInboundSecurityContext) inboundSecurityContext, crypto, ((WSSSecurityProperties)securityProperties).getCallbackHandler(), crypto.getDefaultX509Identifier(),
                    crypto.getDefaultX509Identifier(), null, ((WSSSecurityProperties)securityProperties)
            );
        }
        throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, "noKeyinfo");
    }

    public static InboundSecurityToken getSecurityToken(SecurityTokenReferenceType securityTokenReferenceType, Crypto crypto,
                                                 final CallbackHandler callbackHandler, InboundSecurityContext inboundSecurityContext,
                                                 WSSSecurityProperties securityProperties)
            throws XMLSecurityException {

        //BSP.R5205 is a joke. In real life we have a lot of cases which prevents a one pass processing.
        //Say encrypted Tokens, SignedTokens, Signed-Timestamp first...

        try {
            if (securityTokenReferenceType == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, "noSecTokRef");
            }

            if (securityTokenReferenceType.getAny().size() > 1) {
                ((WSInboundSecurityContext) inboundSecurityContext).handleBSPRule(BSPRule.R3061);
            }
            
            //todo BSP.R3027 KeyName? not supported ATM
            //todo BSP.R3060,BSP.R3025,BSP.R3056 only one Embedded element? Not supported ATM
            final X509DataType x509DataType
                    = XMLSecurityUtils.getQNameType(securityTokenReferenceType.getAny(), WSSConstants.TAG_dsig_X509Data);
            if (x509DataType != null) {
                return new X509DataSecurityTokenImpl((WSInboundSecurityContext) inboundSecurityContext, crypto, callbackHandler,
                        x509DataType, securityTokenReferenceType.getId(),
                        WSSecurityTokenConstants.KeyIdentifier_IssuerSerial,
                        securityProperties);
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
                    ((WSInboundSecurityContext) inboundSecurityContext).handleBSPRule(BSPRule.R3054);
                }
                String encodingType = keyIdentifierType.getEncodingType();

                byte[] binaryContent = null;
                if (WSSConstants.SOAPMESSAGE_NS10_BASE64_ENCODING.equals(encodingType)) {
                    binaryContent = Base64.decodeBase64(keyIdentifierType.getValue());
                } else if (!WSSConstants.NS_SAML10_TYPE.equals(valueType) && !WSSConstants.NS_SAML20_TYPE.equals(valueType)) {
                    if (encodingType == null) {
                        ((WSInboundSecurityContext) inboundSecurityContext).handleBSPRule(BSPRule.R3070);
                    } else {
                        ((WSInboundSecurityContext) inboundSecurityContext).handleBSPRule(BSPRule.R3071);
                    }
                } else if (encodingType != null 
                        && (WSSConstants.NS_SAML10_TYPE.equals(valueType) || WSSConstants.NS_SAML20_TYPE.equals(valueType))) {
                    ((WSInboundSecurityContext) inboundSecurityContext).handleBSPRule(BSPRule.R6604);
                }

                if (WSSConstants.NS_X509_V3_TYPE.equals(valueType)) {
                    return new X509_V3SecurityTokenImpl(
                            (WSInboundSecurityContext) inboundSecurityContext, crypto, callbackHandler,
                            binaryContent, securityTokenReferenceType.getId(), WSSecurityTokenConstants.KeyIdentifier_X509KeyIdentifier,
                            securityProperties);
                } else if (WSSConstants.NS_X509SubjectKeyIdentifier.equals(valueType)) {
                    return new X509SubjectKeyIdentifierSecurityTokenImpl(
                            (WSInboundSecurityContext) inboundSecurityContext, crypto, callbackHandler, binaryContent,
                            securityTokenReferenceType.getId(), WSSecurityTokenConstants.KeyIdentifier_SkiKeyIdentifier,
                            securityProperties);
                } else if (WSSConstants.NS_THUMBPRINT.equals(valueType)) {
                    return new ThumbprintSHA1SecurityTokenImpl(
                            (WSInboundSecurityContext) inboundSecurityContext, crypto, callbackHandler, binaryContent,
                            securityTokenReferenceType.getId(), WSSecurityTokenConstants.KeyIdentifier_ThumbprintIdentifier,
                            securityProperties);
                } else if (WSSConstants.NS_ENCRYPTED_KEY_SHA1.equals(valueType)) {
                    return new EncryptedKeySha1SecurityTokenImpl(
                            (WSInboundSecurityContext) inboundSecurityContext, callbackHandler, keyIdentifierType.getValue(),
                            securityTokenReferenceType.getId(), WSSecurityTokenConstants.KeyIdentifier_EncryptedKeySha1Identifier);
                } else if (WSSConstants.NS_SAML10_TYPE.equals(valueType) || WSSConstants.NS_SAML20_TYPE.equals(valueType)) {
                    if (WSSConstants.NS_SAML20_TYPE.equals(valueType) && !WSSConstants.NS_SAML20_TOKEN_PROFILE_TYPE.equals(tokenType)) {
                        ((WSInboundSecurityContext) inboundSecurityContext).handleBSPRule(BSPRule.R6617);
                    } else if (WSSConstants.NS_SAML10_TYPE.equals(valueType) && !WSSConstants.NS_SAML11_TOKEN_PROFILE_TYPE.equals(tokenType)) {
                        ((WSInboundSecurityContext) inboundSecurityContext).handleBSPRule(BSPRule.R6611);
                    }
                    SecurityTokenProvider<? extends InboundSecurityToken> securityTokenProvider =
                            inboundSecurityContext.getSecurityTokenProvider(keyIdentifierType.getValue());
                    if (securityTokenProvider == null) {
                        throw new WSSecurityException(
                                WSSecurityException.ErrorCode.SECURITY_TOKEN_UNAVAILABLE, "noToken", keyIdentifierType.getValue());
                    }
                    return securityTokenProvider.getSecurityToken();
                } else if (WSSConstants.NS_Kerberos5_AP_REQ_SHA1.equals(valueType)) {
                    SecurityTokenProvider<? extends InboundSecurityToken> securityTokenProvider =
                            inboundSecurityContext.getSecurityTokenProvider(keyIdentifierType.getValue());
                    if (securityTokenProvider != null) {
                        return securityTokenProvider.getSecurityToken();
                    }

                    MessageDigest messageDigest = null;
                    try {
                        messageDigest = MessageDigest.getInstance("SHA-1");
                    } catch (NoSuchAlgorithmException e) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
                    }

                    //ok we have to find the token via digesting...
                    List<SecurityTokenProvider<? extends InboundSecurityToken>> securityTokenProviders = inboundSecurityContext.getRegisteredSecurityTokenProviders();
                    for (int i = 0; i < securityTokenProviders.size(); i++) {
                        SecurityTokenProvider<? extends InboundSecurityToken> tokenProvider = securityTokenProviders.get(i);
                        InboundSecurityToken inboundSecurityToken = tokenProvider.getSecurityToken();
                        if (inboundSecurityToken instanceof KerberosServiceSecurityToken) {
                            KerberosServiceSecurityToken kerberosSecurityToken = (KerberosServiceSecurityToken)inboundSecurityToken;
                            byte[] tokenDigest = messageDigest.digest(kerberosSecurityToken.getBinaryContent());
                            if (Arrays.equals(tokenDigest, binaryContent)) {
                                return inboundSecurityToken;
                            }
                        }
                    }
                    throw new WSSecurityException(
                            WSSecurityException.ErrorCode.SECURITY_TOKEN_UNAVAILABLE, "noToken", keyIdentifierType.getValue());
                } else {
                    //we do enforce BSP compliance here but will fail anyway since we cannot identify the referenced token
                    ((WSInboundSecurityContext) inboundSecurityContext).handleBSPRule(BSPRule.R3063);
                }
            }

            final org.apache.wss4j.binding.wss10.ReferenceType referenceType
                    = XMLSecurityUtils.getQNameType(securityTokenReferenceType.getAny(), WSSConstants.TAG_wsse_Reference);
            if (referenceType != null) {
                //We do not check for BSP.R3023, BSP.R3022, BSP.R3066, BSP.R3067, BSP.R3024, BSP.R3064, BSP.R3211, BSP.R3059

                String uri = referenceType.getURI();
                if (uri == null) {
                    //we do enforce BSP compliance here but will fail anyway since we cannot identify the referenced token
                    ((WSInboundSecurityContext) inboundSecurityContext).handleBSPRule(BSPRule.R3062);
                    throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, "badReferenceURI");
                }
                if (!uri.startsWith("#")) {
                    ((WSInboundSecurityContext) inboundSecurityContext).handleBSPRule(BSPRule.R5204);
                }
                uri = WSSUtils.dropReferenceMarker(uri);
                //referenced BST:*/
                //we have to search BST somewhere in the doc. First we will check for a BST already processed and
                //stored in the context. Otherwise we will abort now.

                //prevent recursive key reference DOS:
                Integer invokeCount = inboundSecurityContext.<Integer>get("" + Thread.currentThread().hashCode());
                if (invokeCount == null) {
                    invokeCount = 0;
                }
                invokeCount++;
                if (invokeCount == 10) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN);
                }
                inboundSecurityContext.put("" + Thread.currentThread().hashCode(), invokeCount);

                SecurityTokenProvider<? extends InboundSecurityToken> securityTokenProvider = inboundSecurityContext.getSecurityTokenProvider(uri);
                if (securityTokenProvider == null) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.SECURITY_TOKEN_UNAVAILABLE, "noToken", uri);
                }
                if (securityTokenProvider.getSecurityToken() instanceof SecurityTokenReference) {
                    ((WSInboundSecurityContext) inboundSecurityContext).handleBSPRule(BSPRule.R3057);
                } else if (securityTokenProvider.getSecurityToken() instanceof X509PKIPathv1SecurityTokenImpl) {
                    String valueType = referenceType.getValueType();
                    if (!WSSConstants.NS_X509PKIPathv1.equals(valueType)) {
                        ((WSInboundSecurityContext) inboundSecurityContext).handleBSPRule(BSPRule.R3058);
                    }
                    if (!WSSConstants.NS_X509PKIPathv1.equals(tokenType)) {
                        ((WSInboundSecurityContext) inboundSecurityContext).handleBSPRule(BSPRule.R5215);
                    }
                } else if (securityTokenProvider.getSecurityToken() instanceof X509SecurityToken) {
                    String valueType = referenceType.getValueType();
                    if (!WSSConstants.NS_X509_V3_TYPE.equals(valueType)) {
                        ((WSInboundSecurityContext) inboundSecurityContext).handleBSPRule(BSPRule.R3058);
                    }
                } else if (securityTokenProvider.getSecurityToken() instanceof UsernameSecurityToken) {
                    String valueType = referenceType.getValueType();
                    if (!WSSConstants.NS_USERNAMETOKEN_PROFILE_UsernameToken.equals(valueType)) {
                        ((WSInboundSecurityContext) inboundSecurityContext).handleBSPRule(BSPRule.R4214);
                    }
                } else if (securityTokenProvider.getSecurityToken() instanceof SamlSecurityToken) {
                    WSSecurityTokenConstants.TokenType samlTokenType = securityTokenProvider.getSecurityToken().getTokenType();
                    if (WSSecurityTokenConstants.Saml20Token.equals(samlTokenType)) {
                        String valueType = referenceType.getValueType();
                        if (valueType != null && !"".equals(valueType)) {
                            ((WSInboundSecurityContext) inboundSecurityContext).handleBSPRule(BSPRule.R6614);
                        }
                        if (!WSSConstants.NS_SAML20_TOKEN_PROFILE_TYPE.equals(tokenType)) {
                            ((WSInboundSecurityContext) inboundSecurityContext).handleBSPRule(BSPRule.R6617);
                        }
                    } else if (WSSecurityTokenConstants.Saml10Token.equals(samlTokenType) &&
                            !WSSConstants.NS_SAML11_TOKEN_PROFILE_TYPE.equals(tokenType)) {
                        ((WSInboundSecurityContext) inboundSecurityContext).handleBSPRule(BSPRule.R6611);
                    }
                }
                
                return securityTokenProvider.getSecurityToken();
            }
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, "noKeyinfo");
        } finally {
            inboundSecurityContext.remove("" + Thread.currentThread().hashCode());
        }
    }

    public static InboundSecurityToken getSecurityToken(KeyValueType keyValueType, final Crypto crypto,
                                                 final CallbackHandler callbackHandler, SecurityContext securityContext)
            throws XMLSecurityException {

        //todo *KeyValueSecurityToken verify() inline in classes
        //todo either handover crypto to verify() or to constructor
        final RSAKeyValueType rsaKeyValueType
                = XMLSecurityUtils.getQNameType(keyValueType.getContent(), WSSConstants.TAG_dsig_RSAKeyValue);
        if (rsaKeyValueType != null) {
            return new RsaKeyValueSecurityTokenImpl(rsaKeyValueType, (WSInboundSecurityContext) securityContext,
                    WSSecurityTokenConstants.KeyIdentifier_KeyValue) {
                @Override
                public void verify() throws XMLSecurityException {
                    crypto.verifyTrust(getPubKey("", null, null));
                }
            };
        }
        final DSAKeyValueType dsaKeyValueType
                = XMLSecurityUtils.getQNameType(keyValueType.getContent(), WSSConstants.TAG_dsig_DSAKeyValue);
        if (dsaKeyValueType != null) {
            return new DsaKeyValueSecurityTokenImpl(dsaKeyValueType, (WSInboundSecurityContext) securityContext,
                    WSSecurityTokenConstants.KeyIdentifier_KeyValue) {
                @Override
                public void verify() throws XMLSecurityException {
                    crypto.verifyTrust(getPubKey("", null, null));
                }
            };
        }
        final ECKeyValueType ecKeyValueType
                = XMLSecurityUtils.getQNameType(keyValueType.getContent(), WSSConstants.TAG_dsig11_ECKeyValue);
        if (ecKeyValueType != null) {
            return new ECKeyValueSecurityTokenImpl(ecKeyValueType, (WSInboundSecurityContext) securityContext,
                    WSSecurityTokenConstants.KeyIdentifier_KeyValue) {
                @Override
                public void verify() throws XMLSecurityException {
                    crypto.verifyTrust(getPubKey("", null, null));
                }
            };
        }
        throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, "unsupportedKeyInfo");
    }
}
