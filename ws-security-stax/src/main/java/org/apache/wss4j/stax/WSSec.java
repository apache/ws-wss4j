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
package org.apache.wss4j.stax;

import java.net.URISyntaxException;

import org.apache.wss4j.common.crypto.WSProviderConfig;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.ext.InboundWSSec;
import org.apache.wss4j.stax.ext.OutboundWSSec;
import org.apache.wss4j.stax.ext.WSSConfigurationException;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.config.Init;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;

/**
 * This is the central class of the streaming webservice-security framework.<br/>
 * Instances of the inbound and outbound security streams can be retrieved
 * with this class.
 */
public class WSSec {
    
    //todo outgoing client setup per policy

    static {
        WSProviderConfig.init();
        try {
            Init.init(WSSec.class.getClassLoader().getResource("wss/wss-config.xml").toURI());
        } catch (XMLSecurityException e) {
            throw new RuntimeException(e.getMessage(), e);
        } catch (URISyntaxException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    /**
     * Creates and configures an outbound streaming security engine
     *
     * @param securityProperties The user-defined security configuration
     * @return A new OutboundWSSec
     * @throws WSSecurityException
     *          if the initialisation failed
     * @throws org.apache.wss4j.stax.ext.WSSConfigurationException
     *          if the configuration is invalid
     */
    public static OutboundWSSec getOutboundWSSec(WSSSecurityProperties securityProperties) throws WSSecurityException {
        if (securityProperties == null) {
            throw new WSSConfigurationException(WSSConfigurationException.ErrorCode.FAILURE, "missingSecurityProperties");
        }

        securityProperties = validateAndApplyDefaultsToOutboundSecurityProperties(securityProperties);
        return new OutboundWSSec(securityProperties);
    }
    
    /**
     * Creates and configures an inbound streaming security engine
     *
     * @param securityProperties The user-defined security configuration
     * @return A new InboundWSSec
     * @throws WSSecurityException
     *          if the initialisation failed
     * @throws org.apache.wss4j.stax.ext.WSSConfigurationException
     *          if the configuration is invalid
     */
    public static InboundWSSec getInboundWSSec(WSSSecurityProperties securityProperties) throws WSSecurityException {
        if (securityProperties == null) {
            throw new WSSConfigurationException(WSSConfigurationException.ErrorCode.FAILURE, "missingSecurityProperties");
        }

        securityProperties = validateAndApplyDefaultsToInboundSecurityProperties(securityProperties);
        return new InboundWSSec(securityProperties);
    }
    
    /**
     * Validates the user supplied configuration and applies default values as apropriate for the outbound security engine
     *
     * @param securityProperties The configuration to validate
     * @return The validated configuration
     * @throws org.apache.wss4j.stax.ext.WSSConfigurationException
     *          if the configuration is invalid
     */
    public static WSSSecurityProperties validateAndApplyDefaultsToOutboundSecurityProperties(WSSSecurityProperties securityProperties) throws WSSConfigurationException {
        if (securityProperties.getOutAction() == null) {
            throw new WSSConfigurationException(WSSConfigurationException.ErrorCode.FAILURE, "noOutputAction");
        }

        for (int i = 0; i < securityProperties.getOutAction().length; i++) {
            XMLSecurityConstants.Action action = securityProperties.getOutAction()[i];
            if (WSSConstants.TIMESTAMP.equals(action)) {
                if (securityProperties.getTimestampTTL() == null) {
                    securityProperties.setTimestampTTL(300);
                }
            } else if (WSSConstants.SIGNATURE.equals(action)) {
                if (securityProperties.getSignatureKeyStore() == null
                    && securityProperties.getSignatureCryptoProperties() == null
                    && securityProperties.getSignatureCrypto() == null) {
                    throw new WSSConfigurationException(WSSConfigurationException.ErrorCode.FAILURE, "signatureKeyStoreNotSet");
                }
                if (securityProperties.getSignatureUser() == null) {
                    throw new WSSConfigurationException(WSSConfigurationException.ErrorCode.FAILURE, "noSignatureUser");
                }
                if (securityProperties.getCallbackHandler() == null
                    && !WSSConstants.NS_XMLDSIG_HMACSHA1.equals(securityProperties.getSignatureAlgorithm())) {
                    throw new WSSConfigurationException(WSSConfigurationException.ErrorCode.FAILURE, "noCallback");
                }
                if (securityProperties.getSignatureAlgorithm() == null) {
                    securityProperties.setSignatureAlgorithm(WSSConstants.NS_XMLDSIG_RSASHA1);
                }
                if (securityProperties.getSignatureDigestAlgorithm() == null) {
                    securityProperties.setSignatureDigestAlgorithm(WSSConstants.NS_XMLDSIG_SHA1);
                }
                if (securityProperties.getSignatureCanonicalizationAlgorithm() == null) {
                    securityProperties.setSignatureCanonicalizationAlgorithm(WSSConstants.NS_C14N_EXCL);
                }
                if (securityProperties.getSignatureKeyIdentifier() == null) {
                    securityProperties.setSignatureKeyIdentifier(WSSecurityTokenConstants.KeyIdentifier_IssuerSerial);
                }
            } else if (WSSConstants.ENCRYPT.equals(action)) {
                if (securityProperties.getEncryptionUseThisCertificate() == null
                        && securityProperties.getEncryptionKeyStore() == null
                        && securityProperties.getEncryptionCryptoProperties() == null
                        && !securityProperties.isUseReqSigCertForEncryption()
                        && securityProperties.isEncryptSymmetricEncrytionKey()
                        && securityProperties.getEncryptionCrypto() == null) {
                    throw new WSSConfigurationException(WSSConfigurationException.ErrorCode.FAILURE, "encryptionKeyStoreNotSet");
                }
                if (securityProperties.getEncryptionUser() == null
                        && securityProperties.getEncryptionUseThisCertificate() == null
                        && !securityProperties.isUseReqSigCertForEncryption()
                        && securityProperties.isEncryptSymmetricEncrytionKey()) {
                    throw new WSSConfigurationException(WSSConfigurationException.ErrorCode.FAILURE, "noEncryptionUser");
                }
                if (securityProperties.getEncryptionSymAlgorithm() == null) {
                    securityProperties.setEncryptionSymAlgorithm(WSSConstants.NS_XENC_AES256);
                }
                if (securityProperties.getEncryptionKeyTransportAlgorithm() == null) {
                    //@see http://www.w3.org/TR/2002/REC-xmlenc-core-20021210/Overview.html#rsa-1_5 :
                    //"RSA-OAEP is RECOMMENDED for the transport of AES keys"
                    //@see http://www.w3.org/TR/2002/REC-xmlenc-core-20021210/Overview.html#rsa-oaep-mgf1p
                    securityProperties.setEncryptionKeyTransportAlgorithm(WSSConstants.NS_XENC_RSAOAEPMGF1P);
                }
                if (securityProperties.getEncryptionKeyIdentifier() == null) {
                    securityProperties.setEncryptionKeyIdentifier(WSSecurityTokenConstants.KeyIdentifier_IssuerSerial);
                }
            } else if (WSSConstants.USERNAMETOKEN.equals(action)) {
                if (securityProperties.getTokenUser() == null) {
                    throw new WSSConfigurationException(WSSConfigurationException.ErrorCode.FAILURE, "noTokenUser");
                }
                if (securityProperties.getCallbackHandler() == null) {
                    throw new WSSConfigurationException(WSSConfigurationException.ErrorCode.FAILURE, "noCallback");
                }
                if (securityProperties.getUsernameTokenPasswordType() == null) {
                    securityProperties.setUsernameTokenPasswordType(WSSConstants.UsernameTokenPasswordType.PASSWORD_DIGEST);
                }
            } else if (WSSConstants.USERNAMETOKEN_SIGNED.equals(action)) {
                if (securityProperties.getTokenUser() == null) {
                    throw new WSSConfigurationException(WSSConfigurationException.ErrorCode.FAILURE, "noTokenUser");
                }
                if (securityProperties.getCallbackHandler() == null) {
                    throw new WSSConfigurationException(WSSConfigurationException.ErrorCode.FAILURE, "noCallback");
                }
                if (securityProperties.getSignatureAlgorithm() == null) {
                    securityProperties.setSignatureAlgorithm(WSSConstants.NS_XMLDSIG_HMACSHA1);
                }
                if (securityProperties.getSignatureDigestAlgorithm() == null) {
                    securityProperties.setSignatureDigestAlgorithm(WSSConstants.NS_XMLDSIG_SHA1);
                }
                if (securityProperties.getSignatureCanonicalizationAlgorithm() == null) {
                    securityProperties.setSignatureCanonicalizationAlgorithm(WSSConstants.NS_C14N_EXCL);
                }
                securityProperties.setSignatureKeyIdentifier(WSSecurityTokenConstants.KeyIdentifier_UsernameTokenReference);
                if (securityProperties.getUsernameTokenPasswordType() == null) {
                    securityProperties.setUsernameTokenPasswordType(WSSConstants.UsernameTokenPasswordType.PASSWORD_DIGEST);
                }
            } else if (WSSConstants.SIGNATURE_WITH_DERIVED_KEY.equals(action)) {
                if (securityProperties.getCallbackHandler() == null) {
                    throw new WSSConfigurationException(WSSConfigurationException.ErrorCode.FAILURE, "noCallback");
                }
                if (securityProperties.getSignatureAlgorithm() == null) {
                    securityProperties.setSignatureAlgorithm(WSSConstants.NS_XMLDSIG_HMACSHA1);
                }
                if (securityProperties.getSignatureDigestAlgorithm() == null) {
                    securityProperties.setSignatureDigestAlgorithm(WSSConstants.NS_XMLDSIG_SHA1);
                }
                if (securityProperties.getSignatureCanonicalizationAlgorithm() == null) {
                    securityProperties.setSignatureCanonicalizationAlgorithm(WSSConstants.NS_C14N_EXCL);
                }
                securityProperties.setSignatureKeyIdentifier(WSSecurityTokenConstants.KeyIdentifier_SecurityTokenDirectReference);
                if (securityProperties.getEncryptionSymAlgorithm() == null) {
                    securityProperties.setEncryptionSymAlgorithm(WSSConstants.NS_XENC_AES256);
                }
                if (securityProperties.getEncryptionKeyTransportAlgorithm() == null) {
                    //@see http://www.w3.org/TR/2002/REC-xmlenc-core-20021210/Overview.html#rsa-1_5 :
                    //"RSA-OAEP is RECOMMENDED for the transport of AES keys"
                    //@see http://www.w3.org/TR/2002/REC-xmlenc-core-20021210/Overview.html#rsa-oaep-mgf1p
                    securityProperties.setEncryptionKeyTransportAlgorithm(WSSConstants.NS_XENC_RSAOAEPMGF1P);
                }
                if (securityProperties.getEncryptionKeyIdentifier() == null) {
                    securityProperties.setEncryptionKeyIdentifier(WSSecurityTokenConstants.KeyIdentifier_X509KeyIdentifier);
                }
                if (securityProperties.getDerivedKeyKeyIdentifier() == null) {
                    securityProperties.setDerivedKeyKeyIdentifier(WSSecurityTokenConstants.KeyIdentifier_X509KeyIdentifier);
                }
                if (securityProperties.getDerivedKeyTokenReference() == null) {
                    securityProperties.setDerivedKeyTokenReference(WSSConstants.DerivedKeyTokenReference.DirectReference);
                }
                if (securityProperties.getDerivedKeyTokenReference() != WSSConstants.DerivedKeyTokenReference.DirectReference) {
                    securityProperties.setDerivedKeyKeyIdentifier(WSSecurityTokenConstants.KeyIdentifier_SecurityTokenDirectReference);
                }
            } else if (WSSConstants.ENCRYPT_WITH_DERIVED_KEY.equals(action)) {
                if (securityProperties.getCallbackHandler() == null) {
                    throw new WSSConfigurationException(WSSConfigurationException.ErrorCode.FAILURE, "noCallback");
                }
                if (securityProperties.getEncryptionUseThisCertificate() == null
                        && securityProperties.getEncryptionKeyStore() == null
                        && !securityProperties.isUseReqSigCertForEncryption()) {
                    throw new WSSConfigurationException(WSSConfigurationException.ErrorCode.FAILURE, "encryptionKeyStoreNotSet");
                }
                if (securityProperties.getEncryptionUser() == null
                        && securityProperties.getEncryptionUseThisCertificate() == null
                        && !securityProperties.isUseReqSigCertForEncryption()) {
                    throw new WSSConfigurationException(WSSConfigurationException.ErrorCode.FAILURE, "noEncryptionUser");
                }
                if (securityProperties.getEncryptionSymAlgorithm() == null) {
                    securityProperties.setEncryptionSymAlgorithm(WSSConstants.NS_XENC_AES256);
                }
                if (securityProperties.getEncryptionKeyTransportAlgorithm() == null) {
                    //@see http://www.w3.org/TR/2002/REC-xmlenc-core-20021210/Overview.html#rsa-1_5 :
                    //"RSA-OAEP is RECOMMENDED for the transport of AES keys"
                    //@see http://www.w3.org/TR/2002/REC-xmlenc-core-20021210/Overview.html#rsa-oaep-mgf1p
                    securityProperties.setEncryptionKeyTransportAlgorithm(WSSConstants.NS_XENC_RSAOAEPMGF1P);
                }
                if (securityProperties.getEncryptionKeyIdentifier() == null) {
                    securityProperties.setEncryptionKeyIdentifier(WSSecurityTokenConstants.KeyIdentifier_X509KeyIdentifier);
                }
                if (securityProperties.getDerivedKeyKeyIdentifier() == null) {
                    securityProperties.setDerivedKeyKeyIdentifier(WSSecurityTokenConstants.KeyIdentifier_X509KeyIdentifier);
                }
                if (securityProperties.getDerivedKeyTokenReference() == null) {
                    securityProperties.setDerivedKeyTokenReference(WSSConstants.DerivedKeyTokenReference.EncryptedKey);
                }
                if (securityProperties.getDerivedKeyTokenReference() != WSSConstants.DerivedKeyTokenReference.DirectReference) {
                    securityProperties.setDerivedKeyKeyIdentifier(WSSecurityTokenConstants.KeyIdentifier_SecurityTokenDirectReference);
                }
            } else if (WSSConstants.SAML_TOKEN_SIGNED.equals(action)) {
                if (securityProperties.getCallbackHandler() == null) {
                    throw new WSSConfigurationException(WSSConfigurationException.ErrorCode.FAILURE, "noCallback");
                }
                if (securityProperties.getSamlCallbackHandler() == null) {
                    throw new WSSConfigurationException(WSSConfigurationException.ErrorCode.FAILURE, "noSAMLCallbackHandler");
                }
                if (securityProperties.getSignatureAlgorithm() == null) {
                    securityProperties.setSignatureAlgorithm(WSSConstants.NS_XMLDSIG_RSASHA1);
                }
                if (securityProperties.getSignatureDigestAlgorithm() == null) {
                    securityProperties.setSignatureDigestAlgorithm(WSSConstants.NS_XMLDSIG_SHA1);
                }
                if (securityProperties.getSignatureCanonicalizationAlgorithm() == null) {
                    securityProperties.setSignatureCanonicalizationAlgorithm(WSSConstants.NS_C14N_EXCL);
                }
                if (securityProperties.getSignatureKeyIdentifier() == null) {
                    securityProperties.setSignatureKeyIdentifier(WSSecurityTokenConstants.KeyIdentifier_SecurityTokenDirectReference);
                }
            } else if (WSSConstants.SAML_TOKEN_UNSIGNED.equals(action) &&
                    (securityProperties.getSamlCallbackHandler() == null)) {
                throw new WSSConfigurationException(WSSConfigurationException.ErrorCode.FAILURE, "noSAMLCallbackHandler");
            } else if (WSSConstants.SIGNATURE_WITH_KERBEROS_TOKEN.equals(action)) {
                if (securityProperties.getCallbackHandler() == null) {
                    throw new WSSConfigurationException(WSSConfigurationException.ErrorCode.FAILURE, "noCallback");
                }
                if (securityProperties.getSignatureAlgorithm() == null) {
                    securityProperties.setSignatureAlgorithm(WSSConstants.NS_XMLDSIG_HMACSHA1);
                }
                if (securityProperties.getSignatureDigestAlgorithm() == null) {
                    securityProperties.setSignatureDigestAlgorithm(WSSConstants.NS_XMLDSIG_SHA1);
                }
                if (securityProperties.getSignatureCanonicalizationAlgorithm() == null) {
                    securityProperties.setSignatureCanonicalizationAlgorithm(WSSConstants.NS_C14N_EXCL);
                }
                if (securityProperties.getSignatureKeyIdentifier() == null) {
                    securityProperties.setSignatureKeyIdentifier(WSSecurityTokenConstants.KeyIdentifier_SecurityTokenDirectReference);
                }
            } else if (WSSConstants.ENCRYPT_WITH_KERBEROS_TOKEN.equals(action)) {
                if (securityProperties.getCallbackHandler() == null) {
                    throw new WSSConfigurationException(WSSConfigurationException.ErrorCode.FAILURE, "noCallback");
                }
                if (securityProperties.getEncryptionSymAlgorithm() == null) {
                    securityProperties.setEncryptionSymAlgorithm(WSSConstants.NS_XENC_AES256);
                }
                if (securityProperties.getSignatureKeyIdentifier() == null) {
                    securityProperties.setSignatureKeyIdentifier(WSSecurityTokenConstants.KeyIdentifier_SecurityTokenDirectReference);
                }
            }
        }
        return new WSSSecurityProperties(securityProperties);
    }

    /**
     * Validates the user supplied configuration and applies default values as apropriate for the inbound security engine
     *
     * @param securityProperties The configuration to validate
     * @return The validated configuration
     * @throws org.apache.wss4j.stax.ext.WSSConfigurationException
     *          if the configuration is invalid
     */
    public static WSSSecurityProperties validateAndApplyDefaultsToInboundSecurityProperties(WSSSecurityProperties securityProperties) throws WSSConfigurationException {
        return new WSSSecurityProperties(securityProperties);
    }
}
