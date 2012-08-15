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

package org.apache.ws.security.str;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.message.token.BinarySecurity;
import org.apache.ws.security.message.token.KerberosSecurity;
import org.apache.ws.security.message.token.PKIPathSecurity;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.message.token.X509Security;
import org.apache.ws.security.saml.ext.AssertionWrapper;

/**
 * This class enforces processing rules for SecurityTokenReferences to various token elements,
 * according to the Basic Security Profile (BSP) specification.
 */
public final class BSPEnforcer {
    
    private BSPEnforcer() {
        //
    }
    
    /**
     * Check that the BinarySecurityToken referenced by the SecurityTokenReference argument 
     * is BSP compliant.
     * @param secRef The SecurityTokenReference to the BinarySecurityToken
     * @param token The BinarySecurityToken
     * @throws WSSecurityException
     */
    public static void checkBinarySecurityBSPCompliance(
        SecurityTokenReference secRef,
        BinarySecurity token
    ) throws WSSecurityException {
        if (secRef.containsReference()) {
            // Check the ValueType attributes
            String valueType = secRef.getReference().getValueType();
            if (((token instanceof X509Security) && !X509Security.X509_V3_TYPE.equals(valueType))
                || ((token instanceof PKIPathSecurity) && !PKIPathSecurity.PKI_TYPE.equals(valueType))
                || ((token instanceof KerberosSecurity) 
                        && !WSConstants.WSS_GSS_KRB_V5_AP_REQ.equals(valueType))) {
                throw new WSSecurityException(
                    WSSecurityException.INVALID_SECURITY_TOKEN, 
                    "invalidValueType", 
                    new Object[]{valueType}
                );
            }
        } else if (secRef.containsKeyIdentifier()) {
            String valueType = secRef.getKeyIdentifierValueType();
            if (!SecurityTokenReference.SKI_URI.equals(valueType) 
                && !SecurityTokenReference.THUMB_URI.equals(valueType)
                && !WSConstants.WSS_KRB_KI_VALUE_TYPE.equals(valueType)) {
                throw new WSSecurityException(
                    WSSecurityException.INVALID_SECURITY_TOKEN, 
                    "invalidValueType", 
                    new Object[]{valueType}
                );
            }
        }
        
        // Check TokenType attributes
        if (token instanceof PKIPathSecurity) {
            String tokenType = secRef.getTokenType();
            if (!PKIPathSecurity.PKI_TYPE.equals(tokenType)) {
                throw new WSSecurityException(
                    WSSecurityException.INVALID_SECURITY_TOKEN, 
                    "invalidTokenType", 
                     new Object[]{tokenType}
                );
            }
        }
    }
    
    /**
     * Check that the EncryptedKey referenced by the SecurityTokenReference argument 
     * is BSP compliant.
     * @param secRef The SecurityTokenReference to the BinarySecurityToken
     * @throws WSSecurityException
     */
    public static void checkEncryptedKeyBSPCompliance(
        SecurityTokenReference secRef
    ) throws WSSecurityException {
        if (secRef.containsKeyIdentifier()) {
            String valueType = secRef.getKeyIdentifierValueType();
            if (!SecurityTokenReference.ENC_KEY_SHA1_URI.equals(valueType)) {
                throw new WSSecurityException(
                    WSSecurityException.INVALID_SECURITY_TOKEN, 
                    "invalidValueType", 
                    new Object[]{valueType}
                );
            }
        }
        
        String tokenType = secRef.getTokenType();
        if (!WSConstants.WSS_ENC_KEY_VALUE_TYPE.equals(tokenType)) {
            throw new WSSecurityException(
                WSSecurityException.INVALID_SECURITY_TOKEN, 
                "invalidTokenType", 
                 new Object[]{tokenType}
            );
        }
    }
    
    /**
     * Check that the SAML token referenced by the SecurityTokenReference argument 
     * is BSP compliant.
     * @param secRef The SecurityTokenReference to the SAML token
     * @param assertion The SAML Token AssertionWrapper object
     * @throws WSSecurityException
     */
    public static void checkSamlTokenBSPCompliance(
        SecurityTokenReference secRef,
        AssertionWrapper assertion
    ) throws WSSecurityException {
        // Check the KeyIdentifier ValueType attributes
        if (secRef.containsKeyIdentifier()) {
            String valueType = secRef.getKeyIdentifierValueType();
            if (assertion.getSaml1() != null 
                && !WSConstants.WSS_SAML_KI_VALUE_TYPE.equals(valueType)) {
                throw new WSSecurityException(
                    WSSecurityException.INVALID_SECURITY_TOKEN, 
                    "invalidValueType", 
                    new Object[]{valueType}
                );
            }
            if (assertion.getSaml2() != null 
                && !WSConstants.WSS_SAML2_KI_VALUE_TYPE.equals(valueType)) {
                throw new WSSecurityException(
                    WSSecurityException.INVALID_SECURITY_TOKEN, 
                    "invalidValueType", 
                    new Object[]{valueType}
                );
            }
            String encoding = secRef.getKeyIdentifierEncodingType();
            if (encoding != null && !"".equals(encoding)) {
                throw new WSSecurityException(
                    WSSecurityException.INVALID_SECURITY_TOKEN, 
                    "badEncodingType", 
                    new Object[]{encoding}
                );
            }
        }
        
        // Check the TokenType attribute
        String tokenType = secRef.getTokenType();
        if (assertion.getSaml1() != null && !WSConstants.WSS_SAML_TOKEN_TYPE.equals(tokenType)) {
            throw new WSSecurityException(
                WSSecurityException.INVALID_SECURITY_TOKEN, 
                "invalidTokenType", 
                 new Object[]{tokenType}
            );
        }
        if (assertion.getSaml2() != null && !WSConstants.WSS_SAML2_TOKEN_TYPE.equals(tokenType)) {
            throw new WSSecurityException(
                WSSecurityException.INVALID_SECURITY_TOKEN, 
                "invalidTokenType", 
                 new Object[]{tokenType}
            );
        }
        
        // Check the ValueType attribute of the Reference for SAML2
        if (assertion.getSaml2() != null && secRef.containsReference()) {
            String valueType = secRef.getReference().getValueType();
            if (valueType != null && !"".equals(valueType)) {
                throw new WSSecurityException(
                    WSSecurityException.INVALID_SECURITY_TOKEN, 
                    "invalidValueType", 
                    new Object[]{valueType}
                );
            }
        }
    }
    
    /**
     * Check that the Username token referenced by the SecurityTokenReference argument 
     * is BSP compliant.
     * @param secRef The SecurityTokenReference to the Username token
     * @throws WSSecurityException
     */
    public static void checkUsernameTokenBSPCompliance(
        SecurityTokenReference secRef
    ) throws WSSecurityException {
        if (!secRef.containsReference()) {
            // BSP does not permit using a KeyIdentifier to refer to a U/T
            throw new WSSecurityException(
                WSSecurityException.FAILED_CHECK, "unsupportedKeyId"
            );
        }
        
        String valueType = secRef.getReference().getValueType();
        if (!WSConstants.WSS_USERNAME_TOKEN_VALUE_TYPE.equals(valueType)) {
            // BSP says the Reference must have a ValueType of UsernameToken
            throw new WSSecurityException(
                WSSecurityException.INVALID_SECURITY,
                "invalidValueType", 
                new Object[]{valueType}
            );
        }
    }

    
}
