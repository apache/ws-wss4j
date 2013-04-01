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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

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
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;

/**
 * This is the central class of the streaming webservice-security framework.<br/>
 * Instances of the inbound and outbound security streams can be retrieved
 * with this class.
 */
public class WSSec {
    
    //todo crl check
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

        //todo encrypt sigconf when original signature was encrypted
        int pos = Arrays.binarySearch(securityProperties.getOutAction(), WSSConstants.SIGNATURE_CONFIRMATION);
        if ((pos >= 0) 
                && (Arrays.binarySearch(securityProperties.getOutAction(), WSSConstants.SIGNATURE) < 0)) {
            List<XMLSecurityConstants.Action> actionList = new ArrayList<XMLSecurityConstants.Action>(securityProperties.getOutAction().length);
            actionList.addAll(Arrays.asList(securityProperties.getOutAction()));
            actionList.add(pos, WSSConstants.SIGNATURE);
            securityProperties.setOutAction(actionList.toArray(new XMLSecurityConstants.Action[securityProperties.getOutAction().length + 1]));
        }

        for (int i = 0; i < securityProperties.getOutAction().length; i++) {
            XMLSecurityConstants.Action action = securityProperties.getOutAction()[i];
            if (WSSConstants.TIMESTAMP.equals(action)) {
                if (securityProperties.getTimestampTTL() == null) {
                    securityProperties.setTimestampTTL(300);
                }
            } else if (WSSConstants.SIGNATURE.equals(action)) {
                if (securityProperties.getSignatureKeyStore() == null) {
                    throw new WSSConfigurationException(WSSConfigurationException.ErrorCode.FAILURE, "signatureKeyStoreNotSet");
                }
                if (securityProperties.getSignatureUser() == null) {
                    throw new WSSConfigurationException(WSSConfigurationException.ErrorCode.FAILURE, "noSignatureUser");
                }
                if (securityProperties.getCallbackHandler() == null) {
                    throw new WSSConfigurationException(WSSConfigurationException.ErrorCode.FAILURE, "noCallback");
                }
                if (securityProperties.getSignatureAlgorithm() == null) {
                    securityProperties.setSignatureAlgorithm("http://www.w3.org/2000/09/xmldsig#rsa-sha1");
                }
                if (securityProperties.getSignatureDigestAlgorithm() == null) {
                    securityProperties.setSignatureDigestAlgorithm("http://www.w3.org/2000/09/xmldsig#sha1");
                }
                if (securityProperties.getSignatureCanonicalizationAlgorithm() == null) {
                    securityProperties.setSignatureCanonicalizationAlgorithm("http://www.w3.org/2001/10/xml-exc-c14n#");
                }
                if (securityProperties.getSignatureKeyIdentifier() == null) {
                    securityProperties.setSignatureKeyIdentifier(WSSecurityTokenConstants.KeyIdentifier_IssuerSerial);
                }
            } else if (WSSConstants.ENCRYPT.equals(action)) {
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
                    securityProperties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#aes256-cbc");
                }
                if (securityProperties.getEncryptionKeyTransportAlgorithm() == null) {
                    //@see http://www.w3.org/TR/2002/REC-xmlenc-core-20021210/Overview.html#rsa-1_5 :
                    //"RSA-OAEP is RECOMMENDED for the transport of AES keys"
                    //@see http://www.w3.org/TR/2002/REC-xmlenc-core-20021210/Overview.html#rsa-oaep-mgf1p
                    securityProperties.setEncryptionKeyTransportAlgorithm("http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p");
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
                    securityProperties.setSignatureAlgorithm("http://www.w3.org/2000/09/xmldsig#hmac-sha1");
                }
                if (securityProperties.getSignatureDigestAlgorithm() == null) {
                    securityProperties.setSignatureDigestAlgorithm("http://www.w3.org/2000/09/xmldsig#sha1");
                }
                if (securityProperties.getSignatureCanonicalizationAlgorithm() == null) {
                    securityProperties.setSignatureCanonicalizationAlgorithm("http://www.w3.org/2001/10/xml-exc-c14n#");
                }
                securityProperties.setSignatureKeyIdentifier(WSSecurityTokenConstants.KeyIdentifier_UsernameTokenReference);
                if (securityProperties.getUsernameTokenPasswordType() == null) {
                    securityProperties.setUsernameTokenPasswordType(WSSConstants.UsernameTokenPasswordType.PASSWORD_DIGEST);
                }
            } else if (WSSConstants.SIGNATURE_CONFIRMATION.equals(action)) {
                securityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_wsse11_SignatureConfirmation, SecurePart.Modifier.Element));
            } else if (WSSConstants.SIGNATURE_WITH_DERIVED_KEY.equals(action)) {
                if (securityProperties.getCallbackHandler() == null) {
                    throw new WSSConfigurationException(WSSConfigurationException.ErrorCode.FAILURE, "noCallback");
                }
                if (securityProperties.getSignatureAlgorithm() == null) {
                    securityProperties.setSignatureAlgorithm("http://www.w3.org/2000/09/xmldsig#hmac-sha1");
                }
                if (securityProperties.getSignatureDigestAlgorithm() == null) {
                    securityProperties.setSignatureDigestAlgorithm("http://www.w3.org/2000/09/xmldsig#sha1");
                }
                if (securityProperties.getSignatureCanonicalizationAlgorithm() == null) {
                    securityProperties.setSignatureCanonicalizationAlgorithm("http://www.w3.org/2001/10/xml-exc-c14n#");
                }
                securityProperties.setSignatureKeyIdentifier(WSSecurityTokenConstants.KeyIdentifier_SecurityTokenDirectReference);
                if (securityProperties.getEncryptionSymAlgorithm() == null) {
                    securityProperties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#aes256-cbc");
                }
                if (securityProperties.getEncryptionKeyTransportAlgorithm() == null) {
                    //@see http://www.w3.org/TR/2002/REC-xmlenc-core-20021210/Overview.html#rsa-1_5 :
                    //"RSA-OAEP is RECOMMENDED for the transport of AES keys"
                    //@see http://www.w3.org/TR/2002/REC-xmlenc-core-20021210/Overview.html#rsa-oaep-mgf1p
                    securityProperties.setEncryptionKeyTransportAlgorithm("http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p");
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
                    securityProperties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#aes256-cbc");
                }
                if (securityProperties.getEncryptionKeyTransportAlgorithm() == null) {
                    //@see http://www.w3.org/TR/2002/REC-xmlenc-core-20021210/Overview.html#rsa-1_5 :
                    //"RSA-OAEP is RECOMMENDED for the transport of AES keys"
                    //@see http://www.w3.org/TR/2002/REC-xmlenc-core-20021210/Overview.html#rsa-oaep-mgf1p
                    securityProperties.setEncryptionKeyTransportAlgorithm("http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p");
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
                if (securityProperties.getSignatureAlgorithm() == null) {
                    securityProperties.setSignatureAlgorithm("http://www.w3.org/2000/09/xmldsig#rsa-sha1");
                }
                if (securityProperties.getSignatureDigestAlgorithm() == null) {
                    securityProperties.setSignatureDigestAlgorithm("http://www.w3.org/2000/09/xmldsig#sha1");
                }
                if (securityProperties.getSignatureCanonicalizationAlgorithm() == null) {
                    securityProperties.setSignatureCanonicalizationAlgorithm("http://www.w3.org/2001/10/xml-exc-c14n#");
                }
                if (securityProperties.getSignatureKeyIdentifier() == null) {
                    securityProperties.setSignatureKeyIdentifier(WSSecurityTokenConstants.KeyIdentifier_SecurityTokenDirectReference);
                }
            } else if (WSSConstants.SAML_TOKEN_UNSIGNED.equals(action) &&
                    (securityProperties.getCallbackHandler() == null)) {
                throw new WSSConfigurationException(WSSConfigurationException.ErrorCode.FAILURE, "noCallback");
            } else if (WSSConstants.SIGNATURE_WITH_KERBEROS_TOKEN.equals(action)) {
                if (securityProperties.getCallbackHandler() == null) {
                    throw new WSSConfigurationException(WSSConfigurationException.ErrorCode.FAILURE, "noCallback");
                }
                if (securityProperties.getSignatureAlgorithm() == null) {
                    securityProperties.setSignatureAlgorithm("http://www.w3.org/2000/09/xmldsig#hmac-sha1");
                }
                if (securityProperties.getSignatureDigestAlgorithm() == null) {
                    securityProperties.setSignatureDigestAlgorithm("http://www.w3.org/2000/09/xmldsig#sha1");
                }
                if (securityProperties.getSignatureCanonicalizationAlgorithm() == null) {
                    securityProperties.setSignatureCanonicalizationAlgorithm("http://www.w3.org/2001/10/xml-exc-c14n#");
                }
                if (securityProperties.getSignatureKeyIdentifier() == null) {
                    securityProperties.setSignatureKeyIdentifier(WSSecurityTokenConstants.KeyIdentifier_SecurityTokenDirectReference);
                }
            } else if (WSSConstants.ENCRYPT_WITH_KERBEROS_TOKEN.equals(action)) {
                if (securityProperties.getCallbackHandler() == null) {
                    throw new WSSConfigurationException(WSSConfigurationException.ErrorCode.FAILURE, "noCallback");
                }
                if (securityProperties.getEncryptionSymAlgorithm() == null) {
                    securityProperties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#aes256-cbc");
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
