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
package org.apache.ws.security.stax.wss;

import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.ws.security.common.crypto.WSProviderConfig;
import org.apache.ws.security.common.ext.WSSecurityException;
import org.apache.ws.security.stax.wss.ext.InboundWSSec;
import org.apache.ws.security.stax.wss.ext.OutboundWSSec;
import org.apache.ws.security.stax.wss.ext.WSSConfigurationException;
import org.apache.ws.security.stax.wss.ext.WSSConstants;
import org.apache.ws.security.stax.wss.ext.WSSSecurityProperties;
import org.apache.xml.security.stax.config.Init;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityException;

/**
 * This is the central class of the streaming webservice-security framework.<br/>
 * Instances of the inbound and outbound security streams can be retrieved
 * with this class.
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class WSSec {
    
    //todo crl check
    //todo outgoing client setup per policy

    static {
        try {
            Init.init(WSSec.class.getClassLoader().getResource("wss/wss-config.xml").toURI());
        } catch (XMLSecurityException e) {
            throw new RuntimeException(e.getMessage(), e);
        } catch (URISyntaxException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
        WSProviderConfig.init();
    }

    /**
     * Creates and configures an outbound streaming security engine
     *
     * @param securityProperties The user-defined security configuration
     * @return A new OutboundWSSec
     * @throws org.apache.ws.security.stax.wss.ext.WSSecurityException
     *          if the initialisation failed
     * @throws org.apache.ws.security.stax.wss.ext.WSSConfigurationException
     *          if the configuration is invalid
     */
    public static OutboundWSSec getOutboundWSSec(WSSSecurityProperties securityProperties) throws WSSecurityException {
        if (securityProperties == null) {
            throw new WSSConfigurationException(WSSecurityException.ErrorCode.FAILURE, "missingSecurityProperties");
        }

        securityProperties = validateAndApplyDefaultsToOutboundSecurityProperties(securityProperties);
        return new OutboundWSSec(securityProperties);
    }

    /**
     * Creates and configures an inbound streaming security engine
     *
     * @param securityProperties The user-defined security configuration
     * @return A new InboundWSSec
     * @throws org.apache.ws.security.stax.wss.ext.WSSecurityException
     *          if the initialisation failed
     * @throws org.apache.ws.security.stax.wss.ext.WSSConfigurationException
     *          if the configuration is invalid
     */
    public static InboundWSSec getInboundWSSec(WSSSecurityProperties securityProperties) throws WSSecurityException {
        if (securityProperties == null) {
            throw new WSSConfigurationException(WSSecurityException.ErrorCode.FAILURE, "missingSecurityProperties");
        }

        securityProperties = validateAndApplyDefaultsToInboundSecurityProperties(securityProperties);
        return new InboundWSSec(securityProperties);
    }

    /**
     * Validates the user supplied configuration and applies default values as apropriate for the outbound security engine
     *
     * @param securityProperties The configuration to validate
     * @return The validated configuration
     * @throws org.apache.ws.security.stax.wss.ext.WSSConfigurationException
     *          if the configuration is invalid
     */
    public static WSSSecurityProperties validateAndApplyDefaultsToOutboundSecurityProperties(WSSSecurityProperties securityProperties) throws WSSConfigurationException {
        if (securityProperties.getOutAction() == null) {
            throw new WSSConfigurationException(WSSecurityException.ErrorCode.FAILURE, "noOutputAction");
        }

        //todo encrypt sigconf when original signature was encrypted
        int pos = Arrays.binarySearch(securityProperties.getOutAction(), WSSConstants.SIGNATURE_CONFIRMATION);
        if (pos >= 0) {
            if (Arrays.binarySearch(securityProperties.getOutAction(), WSSConstants.SIGNATURE) < 0) {
                List<XMLSecurityConstants.Action> actionList = new ArrayList<XMLSecurityConstants.Action>(securityProperties.getOutAction().length);
                actionList.addAll(Arrays.asList(securityProperties.getOutAction()));
                actionList.add(pos, WSSConstants.SIGNATURE);
                securityProperties.setOutAction(actionList.toArray(new XMLSecurityConstants.Action[securityProperties.getOutAction().length + 1]));
            }
        }

        for (int i = 0; i < securityProperties.getOutAction().length; i++) {
            XMLSecurityConstants.Action action = securityProperties.getOutAction()[i];
            if (action.equals(WSSConstants.TIMESTAMP)) {
                if (securityProperties.getTimestampTTL() == null) {
                    securityProperties.setTimestampTTL(300);
                }
            } else if (action.equals(WSSConstants.SIGNATURE)) {
                if (securityProperties.getSignatureKeyStore() == null) {
                    throw new WSSConfigurationException(WSSecurityException.ErrorCode.FAILURE, "signatureKeyStoreNotSet");
                }
                if (securityProperties.getSignatureUser() == null) {
                    throw new WSSConfigurationException(WSSecurityException.ErrorCode.FAILURE, "noSignatureUser");
                }
                if (securityProperties.getCallbackHandler() == null) {
                    throw new WSSConfigurationException(WSSecurityException.ErrorCode.FAILURE, "noCallback");
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
                if (securityProperties.getSignatureKeyIdentifierType() == null) {
                    securityProperties.setSignatureKeyIdentifierType(WSSConstants.WSSKeyIdentifierType.ISSUER_SERIAL);
                }
            } else if (action.equals(WSSConstants.ENCRYPT)) {
                if (securityProperties.getEncryptionUseThisCertificate() == null
                        && securityProperties.getEncryptionKeyStore() == null
                        && !securityProperties.isUseReqSigCertForEncryption()) {
                    throw new WSSConfigurationException(WSSecurityException.ErrorCode.FAILURE, "encryptionKeyStoreNotSet");
                }
                if (securityProperties.getEncryptionUser() == null
                        && securityProperties.getEncryptionUseThisCertificate() == null
                        && !securityProperties.isUseReqSigCertForEncryption()) {
                    throw new WSSConfigurationException(WSSecurityException.ErrorCode.FAILURE, "noEncryptionUser");
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
                if (securityProperties.getEncryptionKeyIdentifierType() == null) {
                    securityProperties.setEncryptionKeyIdentifierType(WSSConstants.WSSKeyIdentifierType.ISSUER_SERIAL);
                }
            } else if (action.equals(WSSConstants.USERNAMETOKEN)) {
                if (securityProperties.getTokenUser() == null) {
                    throw new WSSConfigurationException(WSSecurityException.ErrorCode.FAILURE, "noTokenUser");
                }
                if (securityProperties.getCallbackHandler() == null) {
                    throw new WSSConfigurationException(WSSecurityException.ErrorCode.FAILURE, "noCallback");
                }
                if (securityProperties.getUsernameTokenPasswordType() == null) {
                    securityProperties.setUsernameTokenPasswordType(WSSConstants.UsernameTokenPasswordType.PASSWORD_DIGEST);
                }
            } else if (action.equals(WSSConstants.USERNAMETOKEN_SIGNED)) {
                if (securityProperties.getTokenUser() == null) {
                    throw new WSSConfigurationException(WSSecurityException.ErrorCode.FAILURE, "noTokenUser");
                }
                if (securityProperties.getCallbackHandler() == null) {
                    throw new WSSConfigurationException(WSSecurityException.ErrorCode.FAILURE, "noCallback");
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
                securityProperties.setSignatureKeyIdentifierType(WSSConstants.WSSKeyIdentifierType.USERNAMETOKEN_REFERENCE);
                if (securityProperties.getUsernameTokenPasswordType() == null) {
                    securityProperties.setUsernameTokenPasswordType(WSSConstants.UsernameTokenPasswordType.PASSWORD_DIGEST);
                }
            } else if (action.equals(WSSConstants.SIGNATURE_CONFIRMATION)) {
                securityProperties.addSignaturePart(new SecurePart(WSSConstants.TAG_wsse11_SignatureConfirmation, SecurePart.Modifier.Element));
            } else if (action.equals(WSSConstants.SIGNATURE_WITH_DERIVED_KEY)) {
                if (securityProperties.getCallbackHandler() == null) {
                    throw new WSSConfigurationException(WSSecurityException.ErrorCode.FAILURE, "noCallback");
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
                securityProperties.setSignatureKeyIdentifierType(WSSConstants.WSSKeyIdentifierType.SECURITY_TOKEN_DIRECT_REFERENCE);
                if (securityProperties.getEncryptionSymAlgorithm() == null) {
                    securityProperties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#aes256-cbc");
                }
                if (securityProperties.getEncryptionKeyTransportAlgorithm() == null) {
                    //@see http://www.w3.org/TR/2002/REC-xmlenc-core-20021210/Overview.html#rsa-1_5 :
                    //"RSA-OAEP is RECOMMENDED for the transport of AES keys"
                    //@see http://www.w3.org/TR/2002/REC-xmlenc-core-20021210/Overview.html#rsa-oaep-mgf1p
                    securityProperties.setEncryptionKeyTransportAlgorithm("http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p");
                }
                if (securityProperties.getEncryptionKeyIdentifierType() == null) {
                    securityProperties.setEncryptionKeyIdentifierType(WSSConstants.WSSKeyIdentifierType.X509_KEY_IDENTIFIER);
                }
                if (securityProperties.getDerivedKeyKeyIdentifierType() == null) {
                    securityProperties.setDerivedKeyKeyIdentifierType(WSSConstants.WSSKeyIdentifierType.X509_KEY_IDENTIFIER);
                }
                if (securityProperties.getDerivedKeyTokenReference() == null) {
                    securityProperties.setDerivedKeyTokenReference(WSSConstants.DerivedKeyTokenReference.DirectReference);
                }
                if (securityProperties.getDerivedKeyTokenReference() != WSSConstants.DerivedKeyTokenReference.DirectReference) {
                    securityProperties.setDerivedKeyKeyIdentifierType(WSSConstants.WSSKeyIdentifierType.SECURITY_TOKEN_DIRECT_REFERENCE);
                }
            } else if (action.equals(WSSConstants.ENCRYPT_WITH_DERIVED_KEY)) {
                if (securityProperties.getCallbackHandler() == null) {
                    throw new WSSConfigurationException(WSSecurityException.ErrorCode.FAILURE, "noCallback");
                }
                if (securityProperties.getEncryptionUseThisCertificate() == null
                        && securityProperties.getEncryptionKeyStore() == null
                        && !securityProperties.isUseReqSigCertForEncryption()) {
                    throw new WSSConfigurationException(WSSecurityException.ErrorCode.FAILURE, "encryptionKeyStoreNotSet");
                }
                if (securityProperties.getEncryptionUser() == null
                        && securityProperties.getEncryptionUseThisCertificate() == null
                        && !securityProperties.isUseReqSigCertForEncryption()) {
                    throw new WSSConfigurationException(WSSecurityException.ErrorCode.FAILURE, "noEncryptionUser");
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
                if (securityProperties.getEncryptionKeyIdentifierType() == null) {
                    securityProperties.setEncryptionKeyIdentifierType(WSSConstants.WSSKeyIdentifierType.X509_KEY_IDENTIFIER);
                }
                if (securityProperties.getDerivedKeyKeyIdentifierType() == null) {
                    securityProperties.setDerivedKeyKeyIdentifierType(WSSConstants.WSSKeyIdentifierType.X509_KEY_IDENTIFIER);
                }
                if (securityProperties.getDerivedKeyTokenReference() == null) {
                    securityProperties.setDerivedKeyTokenReference(WSSConstants.DerivedKeyTokenReference.EncryptedKey);
                }
                if (securityProperties.getDerivedKeyTokenReference() != WSSConstants.DerivedKeyTokenReference.DirectReference) {
                    securityProperties.setDerivedKeyKeyIdentifierType(WSSConstants.WSSKeyIdentifierType.SECURITY_TOKEN_DIRECT_REFERENCE);
                }
            } else if (action.equals(WSSConstants.SAML_TOKEN_SIGNED)) {
                if (securityProperties.getCallbackHandler() == null) {
                    throw new WSSConfigurationException(WSSecurityException.ErrorCode.FAILURE, "noCallback");
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
                if (securityProperties.getSignatureKeyIdentifierType() == null) {
                    securityProperties.setSignatureKeyIdentifierType(WSSConstants.WSSKeyIdentifierType.SECURITY_TOKEN_DIRECT_REFERENCE);
                }
            } else if (action.equals(WSSConstants.SAML_TOKEN_UNSIGNED)) {
                if (securityProperties.getCallbackHandler() == null) {
                    throw new WSSConfigurationException(WSSecurityException.ErrorCode.FAILURE, "noCallback");
                }
            }
        }
        //todo clone securityProperties
        return securityProperties;
    }

    /**
     * Validates the user supplied configuration and applies default values as apropriate for the inbound security engine
     *
     * @param securityProperties The configuration to validate
     * @return The validated configuration
     * @throws org.apache.ws.security.stax.wss.ext.WSSConfigurationException
     *          if the configuration is invalid
     */
    public static WSSSecurityProperties validateAndApplyDefaultsToInboundSecurityProperties(WSSSecurityProperties securityProperties) throws WSSConfigurationException {
        //todo clone securityProperties
        return securityProperties;
    }
}
