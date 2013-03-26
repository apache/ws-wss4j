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
package org.apache.wss4j.stax.validate;

import org.apache.commons.codec.binary.Base64;
import org.apache.wss4j.binding.wss10.BinarySecurityTokenType;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.ext.InboundSecurityToken;
import org.apache.wss4j.stax.ext.WSSConfigurationException;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.impl.securityToken.KerberosServiceSecurityToken;
import org.apache.wss4j.stax.impl.securityToken.X509PKIPathv1SecurityToken;
import org.apache.wss4j.stax.impl.securityToken.X509_V3SecurityToken;
import org.apache.xml.security.exceptions.XMLSecurityException;

public class BinarySecurityTokenValidatorImpl implements BinarySecurityTokenValidator {

    private static final transient org.slf4j.Logger log = 
        org.slf4j.LoggerFactory.getLogger(BinarySecurityTokenValidatorImpl.class);

    @Override
    public InboundSecurityToken validate(final BinarySecurityTokenType binarySecurityTokenType,
                                                 final TokenContext tokenContext)
            throws WSSecurityException {

        //only Base64Encoding is supported
        if (!WSSConstants.SOAPMESSAGE_NS10_BASE64_ENCODING.equals(binarySecurityTokenType.getEncodingType())) {
            throw new WSSecurityException(
                    WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, "badEncoding",
                    binarySecurityTokenType.getEncodingType());
        }

        byte[] securityTokenData = Base64.decodeBase64(binarySecurityTokenType.getValue());

        try {
            if (WSSConstants.NS_X509_V3_TYPE.equals(binarySecurityTokenType.getValueType())) {
                Crypto crypto = getCrypto(tokenContext.getWssSecurityProperties());
                X509_V3SecurityToken x509V3SecurityToken = new X509_V3SecurityToken(
                        tokenContext.getWsSecurityContext(),
                        crypto,
                        tokenContext.getWssSecurityProperties().getCallbackHandler(),
                        securityTokenData, binarySecurityTokenType.getId(),
                        WSSConstants.WSSKeyIdentifierType.SECURITY_TOKEN_DIRECT_REFERENCE,
                        tokenContext.getWssSecurityProperties()
                );
                x509V3SecurityToken.setElementPath(tokenContext.getElementPath());
                x509V3SecurityToken.setXMLSecEvent(tokenContext.getFirstXMLSecEvent());
                return x509V3SecurityToken;
            } else if (WSSConstants.NS_X509PKIPathv1.equals(binarySecurityTokenType.getValueType())) {
                Crypto crypto = getCrypto(tokenContext.getWssSecurityProperties());
                X509PKIPathv1SecurityToken x509PKIPathv1SecurityToken = new X509PKIPathv1SecurityToken(
                        tokenContext.getWsSecurityContext(),
                        crypto,
                        tokenContext.getWssSecurityProperties().getCallbackHandler(),
                        securityTokenData, binarySecurityTokenType.getId(),
                        WSSConstants.WSSKeyIdentifierType.SECURITY_TOKEN_DIRECT_REFERENCE,
                        tokenContext.getWssSecurityProperties()
                );
                x509PKIPathv1SecurityToken.setElementPath(tokenContext.getElementPath());
                x509PKIPathv1SecurityToken.setXMLSecEvent(tokenContext.getFirstXMLSecEvent());
                return x509PKIPathv1SecurityToken;
            } else if (WSSConstants.NS_GSS_Kerberos5_AP_REQ.equals(binarySecurityTokenType.getValueType())) {
                KerberosServiceSecurityToken kerberosServiceSecurityToken = new KerberosServiceSecurityToken(
                        tokenContext.getWsSecurityContext(),
                        tokenContext.getWssSecurityProperties().getCallbackHandler(),
                        securityTokenData, binarySecurityTokenType.getValueType(),
                        binarySecurityTokenType.getId(),
                        WSSConstants.WSSKeyIdentifierType.SECURITY_TOKEN_DIRECT_REFERENCE
                );
                kerberosServiceSecurityToken.setElementPath(tokenContext.getElementPath());
                kerberosServiceSecurityToken.setXMLSecEvent(tokenContext.getFirstXMLSecEvent());
                return kerberosServiceSecurityToken;
            } else {
                throw new WSSecurityException(
                        WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, "invalidValueType",
                        binarySecurityTokenType.getValueType());
            }
        } catch (XMLSecurityException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, e);
        }
    }

    protected Crypto getCrypto(WSSSecurityProperties securityProperties) throws WSSConfigurationException {
        Crypto crypto = null;
        try {
            crypto = securityProperties.getSignatureVerificationCrypto();
        } catch (WSSConfigurationException e) {
            log.debug(e.getMessage(), e);
            //ignore
        }
        if (crypto == null) {
            crypto = securityProperties.getDecryptionCrypto();
        }
        return crypto;
    }
}
