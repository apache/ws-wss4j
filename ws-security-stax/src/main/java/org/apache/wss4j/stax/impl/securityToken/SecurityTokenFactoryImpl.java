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

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.x500.X500Principal;

import org.apache.wss4j.binding.wss10.KeyIdentifierType;
import org.apache.wss4j.binding.wss10.SecurityTokenReferenceType;
import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.ext.WSInboundSecurityContext;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.securityToken.KerberosServiceSecurityToken;
import org.apache.wss4j.stax.securityToken.SamlSecurityToken;
import org.apache.wss4j.stax.securityToken.SecurityTokenReference;
import org.apache.wss4j.stax.securityToken.UsernameSecurityToken;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.wss4j.stax.securityToken.X509SecurityToken;
import org.apache.wss4j.stax.utils.WSSUtils;
import org.apache.xml.security.binding.xmldsig.DSAKeyValueType;
import org.apache.xml.security.binding.xmldsig.KeyInfoType;
import org.apache.xml.security.binding.xmldsig.KeyValueType;
import org.apache.xml.security.binding.xmldsig.RSAKeyValueType;
import org.apache.xml.security.binding.xmldsig.X509DataType;
import org.apache.xml.security.binding.xmldsig.X509IssuerSerialType;
import org.apache.xml.security.binding.xmldsig11.ECKeyValueType;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.InboundSecurityContext;
import org.apache.xml.security.stax.ext.SecurityContext;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.stax.ext.XMLSecurityUtils;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.apache.xml.security.stax.securityToken.InboundSecurityToken;
import org.apache.xml.security.stax.securityToken.SecurityTokenFactory;
import org.apache.xml.security.stax.securityToken.SecurityTokenProvider;
import org.apache.xml.security.utils.XMLUtils;

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
                    = XMLSecurityUtils.getQNameType(keyInfoType.getContent(), WSSConstants.TAG_WSSE_SECURITY_TOKEN_REFERENCE);
            if (securityTokenReferenceType != null) {
                return getSecurityToken(securityTokenReferenceType, crypto,
                                        ((WSSSecurityProperties)securityProperties).getCallbackHandler(), inboundSecurityContext,
                                        (WSSSecurityProperties)securityProperties);
            }
            final KeyValueType keyValueType
                    = XMLSecurityUtils.getQNameType(keyInfoType.getContent(), WSSConstants.TAG_dsig_KeyValue);
            if (keyValueType != null) {
                return getSecurityToken(keyValueType, crypto, ((WSSSecurityProperties)securityProperties).getCallbackHandler(),
                                        inboundSecurityContext,
                                        (WSSSecurityProperties)securityProperties);
            }

        } else if (crypto != null && crypto.getDefaultX509Identifier() != null) {
            return new X509DefaultSecurityTokenImpl(
                    (WSInboundSecurityContext) inboundSecurityContext, crypto,
                    ((WSSSecurityProperties)securityProperties).getCallbackHandler(), crypto.getDefaultX509Identifier(),
                    crypto.getDefaultX509Identifier(), WSSecurityTokenConstants.KeyIdentifier_NoKeyInfo,
                    (WSSSecurityProperties)securityProperties
            );
        }
        throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, "noKeyinfo");
    }

    public static InboundSecurityToken getSecurityToken(SecurityTokenReferenceType securityTokenReferenceType,
                                                        Crypto crypto,
                                                        final CallbackHandler callbackHandler,
                                                        InboundSecurityContext inboundSecurityContext,
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

            if (securityTokenReferenceType.getId() == null) {
                securityTokenReferenceType.setId(IDGenerator.generateID(null));
            }

            //todo BSP.R3027 KeyName? not supported ATM
            //todo BSP.R3060,BSP.R3025,BSP.R3056 only one Embedded element? Not supported ATM
            final X509DataType x509DataType
                    = XMLSecurityUtils.getQNameType(securityTokenReferenceType.getAny(), WSSConstants.TAG_dsig_X509Data);
            if (x509DataType != null) {
                InboundSecurityToken securityToken =
                    getSecurityToken(x509DataType, securityTokenReferenceType.getId(), crypto, callbackHandler,
                                     inboundSecurityContext, securityProperties);
                if (securityToken != null) {
                    return securityToken;
                }
            }

            String tokenType =
                    XMLSecurityUtils.getQNameAttribute(
                        securityTokenReferenceType.getOtherAttributes(), WSSConstants.ATT_WSSE11_TOKEN_TYPE);

            final KeyIdentifierType keyIdentifierType
                    = XMLSecurityUtils.getQNameType(securityTokenReferenceType.getAny(), WSSConstants.TAG_WSSE_KEY_IDENTIFIER);
            if (keyIdentifierType != null) {
                InboundSecurityToken securityToken =
                    getSecurityToken(keyIdentifierType, securityTokenReferenceType.getId(), tokenType, crypto,
                                     callbackHandler, inboundSecurityContext, securityProperties);
                if (securityToken != null) {
                    return securityToken;
                }
            }

            final org.apache.wss4j.binding.wss10.ReferenceType referenceType
                    = XMLSecurityUtils.getQNameType(securityTokenReferenceType.getAny(), WSSConstants.TAG_WSSE_REFERENCE);
            if (referenceType != null) {
                //We do not check for BSP.R3023, BSP.R3022, BSP.R3066, BSP.R3067, BSP.R3024, BSP.R3064, BSP.R3211, BSP.R3059
                return getSecurityToken(referenceType, tokenType, inboundSecurityContext, securityProperties);
            }
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, "noKeyinfo");
        } finally {
            inboundSecurityContext.remove("" + Thread.currentThread().hashCode());
        }
    }

    private static InboundSecurityToken getSecurityToken(X509DataType x509DataType,
                                                         String securityTokenReferenceId,
                                                         Crypto crypto,
                                                         final CallbackHandler callbackHandler,
                                                         InboundSecurityContext inboundSecurityContext,
                                                         WSSSecurityProperties securityProperties)
                                                             throws XMLSecurityException {
        //Issuer Serial
        X509IssuerSerialType x509IssuerSerialType = XMLSecurityUtils.getQNameType(
                x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName(), WSSConstants.TAG_dsig_X509IssuerSerial);
        if (x509IssuerSerialType != null) {
            //first look if the token is included in the message (necessary for TokenInclusion policy)...
            List<SecurityTokenProvider<? extends InboundSecurityToken>> securityTokenProviders =
                    inboundSecurityContext.getRegisteredSecurityTokenProviders();
            for (int i = 0; i < securityTokenProviders.size(); i++) {
                SecurityTokenProvider<? extends InboundSecurityToken> tokenProvider = securityTokenProviders.get(i);
                InboundSecurityToken inboundSecurityToken = tokenProvider.getSecurityToken();
                if (inboundSecurityToken instanceof X509SecurityToken) {
                    X509SecurityToken x509SecurityToken = (X509SecurityToken) inboundSecurityToken;

                    final X509Certificate x509Certificate = x509SecurityToken.getX509Certificates()[0];
                    Principal principal = new X500Principal(x509IssuerSerialType.getX509IssuerName());
                    if (x509Certificate.getSerialNumber().compareTo(x509IssuerSerialType.getX509SerialNumber()) == 0
                        && x509Certificate.getIssuerX500Principal().equals(principal)) {
                        return createSecurityTokenProxy(inboundSecurityToken,
                                WSSecurityTokenConstants.KeyIdentifier_IssuerSerial);
                    }
                }
            }
            //...then if none is found create a new SecurityToken instance
            return new X509IssuerSerialTokenImpl(
                    (WSInboundSecurityContext) inboundSecurityContext, crypto, callbackHandler, x509IssuerSerialType,
                    securityTokenReferenceId, securityProperties);
        }

        //Subject Key Identifier
        byte[] skiBytes =
                XMLSecurityUtils.getQNameType(
                        x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName(),
                        XMLSecurityConstants.TAG_dsig_X509SKI
                );
        if (skiBytes != null) {
            return new X509SKISecurityTokenImpl(
                    (WSInboundSecurityContext) inboundSecurityContext, crypto, callbackHandler, skiBytes,
                    securityTokenReferenceId, securityProperties);
        }

        //X509Certificate
        byte[] x509CertificateBytes = XMLSecurityUtils.getQNameType(
                x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName(), WSSConstants.TAG_dsig_X509Certificate);
        if (x509CertificateBytes != null) {
            return new X509V3SecurityTokenImpl(
                    (WSInboundSecurityContext) inboundSecurityContext, crypto, callbackHandler,
                    x509CertificateBytes, securityTokenReferenceId, securityProperties);
        }

        return null;
    }

    private static InboundSecurityToken getSecurityToken(KeyIdentifierType keyIdentifierType,
                                                         String securityTokenReferenceId,
                                                         String tokenType,
                                                         Crypto crypto,
                                                         final CallbackHandler callbackHandler,
                                                         InboundSecurityContext inboundSecurityContext,
                                                         WSSSecurityProperties securityProperties)
                                                             throws XMLSecurityException {
        String valueType = keyIdentifierType.getValueType();
        if (valueType == null) {
            ((WSInboundSecurityContext) inboundSecurityContext).handleBSPRule(BSPRule.R3054);
        }
        String encodingType = keyIdentifierType.getEncodingType();

        byte[] binaryContent = null;
        if (WSSConstants.SOAPMESSAGE_NS10_BASE64_ENCODING.equals(encodingType)) {
            binaryContent = XMLUtils.decode(keyIdentifierType.getValue());
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
            return new X509V3SecurityTokenImpl(
                    (WSInboundSecurityContext) inboundSecurityContext, crypto, callbackHandler,
                    binaryContent, securityTokenReferenceId, securityProperties);
        } else if (WSSConstants.NS_X509_SKI.equals(valueType)) {
            return new X509SKISecurityTokenImpl(
                    (WSInboundSecurityContext) inboundSecurityContext, crypto, callbackHandler, binaryContent,
                    securityTokenReferenceId, securityProperties);
        } else if (WSSConstants.NS_THUMBPRINT.equals(valueType)) {
            try {
                MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
                //first look if the token is included in the message (necessary for TokenInclusion policy)...
                List<SecurityTokenProvider<? extends InboundSecurityToken>> securityTokenProviders =
                        inboundSecurityContext.getRegisteredSecurityTokenProviders();
                for (int i = 0; i < securityTokenProviders.size(); i++) {
                    SecurityTokenProvider<? extends InboundSecurityToken> tokenProvider = securityTokenProviders.get(i);
                    InboundSecurityToken inboundSecurityToken = tokenProvider.getSecurityToken();
                    if (inboundSecurityToken instanceof X509SecurityToken) {
                        X509SecurityToken x509SecurityToken = (X509SecurityToken)inboundSecurityToken;
                        byte[] tokenDigest = messageDigest.digest(x509SecurityToken.getX509Certificates()[0].getEncoded());

                        if (Arrays.equals(tokenDigest, binaryContent)) {
                            return createSecurityTokenProxy(inboundSecurityToken,
                                    WSSecurityTokenConstants.KEYIDENTIFIER_THUMBPRINT_IDENTIFIER);
                        }
                    }
                }
            } catch (NoSuchAlgorithmException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
            } catch (CertificateEncodingException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN);
            }

            //...then if none is found create a new SecurityToken instance
            return new X509ThumbprintSHA1SecurityTokenImpl(
                    (WSInboundSecurityContext) inboundSecurityContext, crypto, callbackHandler, binaryContent,
                    securityTokenReferenceId, securityProperties);
        } else if (WSSConstants.NS_ENCRYPTED_KEY_SHA1.equals(valueType)) {
            return new EncryptedKeySha1SecurityTokenImpl(
                    (WSInboundSecurityContext) inboundSecurityContext, callbackHandler, keyIdentifierType.getValue(),
                    securityTokenReferenceId);
        } else if (WSSConstants.NS_SAML10_TYPE.equals(valueType) || WSSConstants.NS_SAML20_TYPE.equals(valueType)) {
            if (WSSConstants.NS_SAML20_TYPE.equals(valueType) && !WSSConstants.NS_SAML20_TOKEN_PROFILE_TYPE.equals(tokenType)) {
                ((WSInboundSecurityContext) inboundSecurityContext).handleBSPRule(BSPRule.R6617);
            } else if (WSSConstants.NS_SAML10_TYPE.equals(valueType)
                && !WSSConstants.NS_SAML11_TOKEN_PROFILE_TYPE.equals(tokenType)) {
                ((WSInboundSecurityContext) inboundSecurityContext).handleBSPRule(BSPRule.R6611);
            }
            SecurityTokenProvider<? extends InboundSecurityToken> securityTokenProvider =
                    inboundSecurityContext.getSecurityTokenProvider(keyIdentifierType.getValue());
            if (securityTokenProvider != null) {
                return createSecurityTokenProxy(securityTokenProvider.getSecurityToken(),
                    WSSecurityTokenConstants.KEYIDENTIFIER_SECURITY_TOKEN_DIRECT_REFERENCE);
            }

            // Delegate to a CallbackHandler, in case the token is not in the request
            return new SamlSecurityTokenImpl((WSInboundSecurityContext) inboundSecurityContext,
                                             keyIdentifierType.getValue(),
                                             WSSecurityTokenConstants.KEYIDENTIFIER_EXTERNAL_REFERENCE,
                                             securityProperties);
        } else if (WSSConstants.NS_KERBEROS5_AP_REQ_SHA1.equals(valueType)) {
            SecurityTokenProvider<? extends InboundSecurityToken> securityTokenProvider =
                    inboundSecurityContext.getSecurityTokenProvider(keyIdentifierType.getValue());
            if (securityTokenProvider != null) {
                return createSecurityTokenProxy(securityTokenProvider.getSecurityToken(),
                        WSSecurityTokenConstants.KEYIDENTIFIER_SECURITY_TOKEN_DIRECT_REFERENCE);
            }

            try {
                //ok we have to find the token via digesting...
                MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
                List<SecurityTokenProvider<? extends InboundSecurityToken>> securityTokenProviders =
                        inboundSecurityContext.getRegisteredSecurityTokenProviders();
                for (int i = 0; i < securityTokenProviders.size(); i++) {
                    SecurityTokenProvider<? extends InboundSecurityToken> tokenProvider = securityTokenProviders.get(i);
                    InboundSecurityToken inboundSecurityToken = tokenProvider.getSecurityToken();
                    if (inboundSecurityToken instanceof KerberosServiceSecurityToken) {
                        KerberosServiceSecurityToken kerberosSecurityToken =
                            (KerberosServiceSecurityToken)inboundSecurityToken;
                        byte[] tokenDigest = messageDigest.digest(kerberosSecurityToken.getBinaryContent());
                        if (Arrays.equals(tokenDigest, binaryContent)) {
                            return createSecurityTokenProxy(inboundSecurityToken,
                                    WSSecurityTokenConstants.KEYIDENTIFIER_THUMBPRINT_IDENTIFIER);
                        }
                    }
                }
            } catch (NoSuchAlgorithmException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
            }

            // Finally, just delegate to a Callback as per EncryptedKeySHA1
            return new EncryptedKeySha1SecurityTokenImpl(
                    (WSInboundSecurityContext) inboundSecurityContext, callbackHandler,
                    keyIdentifierType.getValue(), securityTokenReferenceId);
        } else {
            //we do enforce BSP compliance here but will fail anyway since we cannot identify the referenced token
            ((WSInboundSecurityContext) inboundSecurityContext).handleBSPRule(BSPRule.R3063);
        }

        return null;
    }

    private static InboundSecurityToken getSecurityToken(org.apache.wss4j.binding.wss10.ReferenceType referenceType,
                                                         String tokenType,
                                                         InboundSecurityContext inboundSecurityContext,
                                                         WSSSecurityProperties securityProperties)
                                                             throws XMLSecurityException {
        String uri = referenceType.getURI();
        if (uri == null) {
            //we do enforce BSP compliance here but will fail anyway since we cannot identify the referenced token
            ((WSInboundSecurityContext) inboundSecurityContext).handleBSPRule(BSPRule.R3062);
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, "badReferenceURI");
        }
        boolean included = true;
        if (!uri.startsWith("#")) {
            included = false;
            // Delegate to a CallbackHandler, in case the token is not in the request
            try {
                return new ExternalSecurityTokenImpl((WSInboundSecurityContext) inboundSecurityContext,
                                             uri,
                                             WSSecurityTokenConstants.KEYIDENTIFIER_EXTERNAL_REFERENCE,
                                             securityProperties, false);
            } catch (WSSecurityException ex) { //NOPMD
                // just continue
            }
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

        SecurityTokenProvider<? extends InboundSecurityToken> securityTokenProvider =
                inboundSecurityContext.getSecurityTokenProvider(uri);
        if (securityTokenProvider == null) {
            // Delegate to a CallbackHandler, in case the token is not in the request
            return new ExternalSecurityTokenImpl((WSInboundSecurityContext) inboundSecurityContext,
                                             uri,
                                             WSSecurityTokenConstants.KEYIDENTIFIER_EXTERNAL_REFERENCE,
                                             securityProperties, included);
        }
        if (securityTokenProvider.getSecurityToken() instanceof SecurityTokenReference) {
            ((WSInboundSecurityContext) inboundSecurityContext).handleBSPRule(BSPRule.R3057);
        } else if (securityTokenProvider.getSecurityToken() instanceof X509PKIPathv1SecurityTokenImpl) {
            String valueType = referenceType.getValueType();
            if (!WSSConstants.NS_X509_PKIPATH_V1.equals(valueType)) {
                ((WSInboundSecurityContext) inboundSecurityContext).handleBSPRule(BSPRule.R3058);
            }
            if (!WSSConstants.NS_X509_PKIPATH_V1.equals(tokenType)) {
                ((WSInboundSecurityContext) inboundSecurityContext).handleBSPRule(BSPRule.R5215);
            }
        } else if (securityTokenProvider.getSecurityToken() instanceof X509SecurityToken) {
            String valueType = referenceType.getValueType();
            if (!WSSConstants.NS_X509_V3_TYPE.equals(valueType)) {
                ((WSInboundSecurityContext) inboundSecurityContext).handleBSPRule(BSPRule.R3058);
            }
        } else if (securityTokenProvider.getSecurityToken() instanceof UsernameSecurityToken) {
            String valueType = referenceType.getValueType();
            if (!WSSConstants.NS_USERNAMETOKEN_PROFILE_USERNAME_TOKEN.equals(valueType)) {
                ((WSInboundSecurityContext) inboundSecurityContext).handleBSPRule(BSPRule.R4214);
            }
        } else if (securityTokenProvider.getSecurityToken() instanceof SamlSecurityToken) {
            WSSecurityTokenConstants.TokenType samlTokenType = securityTokenProvider.getSecurityToken().getTokenType();
            if (WSSecurityTokenConstants.SAML_20_TOKEN.equals(samlTokenType)) {
                String valueType = referenceType.getValueType();
                if (valueType != null && !"".equals(valueType)) {
                    ((WSInboundSecurityContext) inboundSecurityContext).handleBSPRule(BSPRule.R6614);
                }
                if (!WSSConstants.NS_SAML20_TOKEN_PROFILE_TYPE.equals(tokenType)) {
                    ((WSInboundSecurityContext) inboundSecurityContext).handleBSPRule(BSPRule.R6617);
                }
            } else if (WSSecurityTokenConstants.SAML_10_TOKEN.equals(samlTokenType)
                && !WSSConstants.NS_SAML11_TOKEN_PROFILE_TYPE.equals(tokenType)) {
                ((WSInboundSecurityContext) inboundSecurityContext).handleBSPRule(BSPRule.R6611);
            }
        }


        return createSecurityTokenProxy(securityTokenProvider.getSecurityToken(),
                WSSecurityTokenConstants.KEYIDENTIFIER_SECURITY_TOKEN_DIRECT_REFERENCE);
    }

    public static InboundSecurityToken getSecurityToken(KeyValueType keyValueType, final Crypto crypto,
                                                 final CallbackHandler callbackHandler, SecurityContext securityContext,
                                                 WSSSecurityProperties securityProperties)
            throws XMLSecurityException {

        final RSAKeyValueType rsaKeyValueType
                = XMLSecurityUtils.getQNameType(keyValueType.getContent(), WSSConstants.TAG_dsig_RSAKeyValue);
        if (rsaKeyValueType != null) {
            return new RsaKeyValueSecurityTokenImpl(rsaKeyValueType, (WSInboundSecurityContext) securityContext, crypto,
                                                    callbackHandler, securityProperties);
        }

        final DSAKeyValueType dsaKeyValueType
                = XMLSecurityUtils.getQNameType(keyValueType.getContent(), WSSConstants.TAG_dsig_DSAKeyValue);
        if (dsaKeyValueType != null) {
            return new DsaKeyValueSecurityTokenImpl(dsaKeyValueType, (WSInboundSecurityContext) securityContext, crypto,
                                                    callbackHandler, securityProperties);
        }

        final ECKeyValueType ecKeyValueType
                = XMLSecurityUtils.getQNameType(keyValueType.getContent(), WSSConstants.TAG_dsig11_ECKeyValue);
        if (ecKeyValueType != null) {
            return new ECKeyValueSecurityTokenImpl(ecKeyValueType, (WSInboundSecurityContext) securityContext, crypto,
                                                   callbackHandler, securityProperties);
        }
        throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, "unsupportedKeyInfo");
    }

    private static InboundSecurityToken createSecurityTokenProxy(
            final InboundSecurityToken inboundSecurityToken,
            final WSSecurityTokenConstants.KeyIdentifier keyIdentifier) {

        List<Class<?>> implementedInterfaces = new ArrayList<>();
        getImplementedInterfaces(inboundSecurityToken.getClass(), implementedInterfaces);
        Class<?>[] interfaces = implementedInterfaces.toArray(new Class<?>[implementedInterfaces.size()]);

        return (InboundSecurityToken) Proxy.newProxyInstance(
                inboundSecurityToken.getClass().getClassLoader(),
                interfaces,
                new InvocationHandler() {

                    @Override
                    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                        if (method.getName().equals("getKeyIdentifier")) {
                            return keyIdentifier;
                        }
                        try {
                            return method.invoke(inboundSecurityToken, args);
                        } catch (InvocationTargetException e) {
                            throw e.getTargetException();
                        }
                    }
                }
        );
    }

    private static void getImplementedInterfaces(Class<?> clazz, List<Class<?>> interfaceList) {
        if (clazz == null) {
            return;
        }
        Class<?>[] interfaces = clazz.getInterfaces();
        for (int i = 0; i < interfaces.length; i++) {
            Class<?> anInterface = interfaces[i];

            if (!interfaceList.contains(anInterface)) {
                interfaceList.add(anInterface);
            }
            getImplementedInterfaces(anInterface, interfaceList);
        }
        getImplementedInterfaces(clazz.getSuperclass(), interfaceList);
    }
}
