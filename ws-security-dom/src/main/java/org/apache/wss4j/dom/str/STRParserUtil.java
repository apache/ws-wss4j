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

package org.apache.wss4j.dom.str;

import java.util.List;

import javax.security.auth.callback.Callback;

import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSDocInfo;
import org.apache.wss4j.dom.WSSecurityEngine;
import org.apache.wss4j.dom.WSSecurityEngineResult;
import org.apache.wss4j.dom.bsp.BSPEnforcer;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.message.token.BinarySecurity;
import org.apache.wss4j.dom.message.token.KerberosSecurity;
import org.apache.wss4j.dom.message.token.PKIPathSecurity;
import org.apache.wss4j.dom.message.token.SecurityTokenReference;
import org.apache.wss4j.dom.message.token.X509Security;
import org.apache.wss4j.dom.processor.Processor;
import org.w3c.dom.Element;

/**
 * Some utilities for the STRParsers.
 */
public final class STRParserUtil {
    
    private STRParserUtil() {
        // complete
    }
    
    /**
     * Get an SamlAssertionWrapper object from parsing a SecurityTokenReference that uses
     * a KeyIdentifier that points to a SAML Assertion.
     * 
     * @param secRef the SecurityTokenReference to the SAML Assertion
     * @param strElement The SecurityTokenReference DOM element
     * @param request The RequestData instance used to obtain configuration
     * @param wsDocInfo The WSDocInfo object that holds previous results
     * @return an SamlAssertionWrapper object
     * @throws WSSecurityException
     */
    public static SamlAssertionWrapper getAssertionFromKeyIdentifier(
        SecurityTokenReference secRef,
        Element strElement,
        RequestData request,
        WSDocInfo wsDocInfo
    ) throws WSSecurityException {
        String keyIdentifierValue = secRef.getKeyIdentifierValue();
        String type = secRef.getKeyIdentifierValueType();
        WSSecurityEngineResult result = wsDocInfo.getResult(keyIdentifierValue);

        SamlAssertionWrapper samlAssertion = null;
        Element token = null;
        if (result != null) {
            samlAssertion =
                (SamlAssertionWrapper)result.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
            return samlAssertion;
        } else {
            token = 
                secRef.findProcessedTokenElement(
                    strElement.getOwnerDocument(), wsDocInfo,
                    request.getCallbackHandler(),
                    keyIdentifierValue, type
                );
            if (token != null) {
                if (!"Assertion".equals(token.getLocalName())) {
                    throw new WSSecurityException(
                        WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity"
                    );
                }
                return new SamlAssertionWrapper(token);
            }
            token = 
                secRef.findUnprocessedTokenElement(
                    strElement.getOwnerDocument(), wsDocInfo,
                    request.getCallbackHandler(), keyIdentifierValue, type
                );
            
            if (token == null || !"Assertion".equals(token.getLocalName())) {
                throw new WSSecurityException(
                    WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity"
                );
            }
            Processor proc = request.getWssConfig().getProcessor(WSSecurityEngine.SAML_TOKEN);
            List<WSSecurityEngineResult> samlResult =
                proc.handleToken(token, request, wsDocInfo);
            return 
                (SamlAssertionWrapper)samlResult.get(0).get(
                    WSSecurityEngineResult.TAG_SAML_ASSERTION
                );
        }
    }
    

    /**
     * Check that the BinarySecurityToken referenced by the SecurityTokenReference argument 
     * is BSP compliant.
     * @param secRef The SecurityTokenReference to the BinarySecurityToken
     * @param token The BinarySecurityToken
     * @param bspEnforcer a BSPEnforcer instance to enforce BSP rules
     * @throws WSSecurityException
     */
    public static void checkBinarySecurityBSPCompliance(
        SecurityTokenReference secRef,
        BinarySecurity token,
        BSPEnforcer bspEnforcer
    ) throws WSSecurityException {
        if (secRef.containsReference()) {
            // Check the ValueType attributes
            String valueType = secRef.getReference().getValueType();
            if (token instanceof X509Security && !X509Security.X509_V3_TYPE.equals(valueType)
                || token instanceof PKIPathSecurity && !PKIPathSecurity.PKI_TYPE.equals(valueType)
                || token instanceof KerberosSecurity 
                        && !(valueType == null || "".equals(valueType))
                        && !WSConstants.WSS_GSS_KRB_V5_AP_REQ.equals(valueType)) {
                bspEnforcer.handleBSPRule(BSPRule.R3058);
            }
        } else if (secRef.containsKeyIdentifier()) {
            String valueType = secRef.getKeyIdentifierValueType();
            if (!SecurityTokenReference.SKI_URI.equals(valueType) 
                && !SecurityTokenReference.THUMB_URI.equals(valueType)
                && !WSConstants.WSS_KRB_KI_VALUE_TYPE.equals(valueType)
                && !X509Security.X509_V3_TYPE.equals(valueType)) {
                bspEnforcer.handleBSPRule(BSPRule.R3063);
            }
        }
        
        // Check TokenType attributes
        if (token instanceof PKIPathSecurity) {
            String tokenType = secRef.getTokenType();
            if (!PKIPathSecurity.PKI_TYPE.equals(tokenType)) {
                bspEnforcer.handleBSPRule(BSPRule.R5215);
            }
        }
    }
    
    /**
     * Check that the EncryptedKey referenced by the SecurityTokenReference argument 
     * is BSP compliant.
     * @param secRef The SecurityTokenReference to the BinarySecurityToken
     * @param bspEnforcer a BSPEnforcer instance to enforce BSP rules
     * @throws WSSecurityException
     */
    public static void checkEncryptedKeyBSPCompliance(
        SecurityTokenReference secRef, BSPEnforcer bspEnforcer
    ) throws WSSecurityException {
        if (secRef.containsKeyIdentifier()) {
            String valueType = secRef.getKeyIdentifierValueType();
            if (!SecurityTokenReference.ENC_KEY_SHA1_URI.equals(valueType)) {
                bspEnforcer.handleBSPRule(BSPRule.R3063);
            }
        }
        
        String tokenType = secRef.getTokenType();
        if (!WSConstants.WSS_ENC_KEY_VALUE_TYPE.equals(tokenType)) {
            bspEnforcer.handleBSPRule(BSPRule.R5215);
        }
    }
    
    /**
     * Check that the SAML token referenced by the SecurityTokenReference argument 
     * is BSP compliant.
     * @param secRef The SecurityTokenReference to the SAML token
     * @param samlAssertion The SAML Token SamlAssertionWrapper object
     * @param bspEnforcer a BSPEnforcer instance to enforce BSP rules
     * @throws WSSecurityException
     */
    public static void checkSamlTokenBSPCompliance(
        SecurityTokenReference secRef,
        SamlAssertionWrapper samlAssertion,
        BSPEnforcer bspEnforcer
    ) throws WSSecurityException {
        // Check the KeyIdentifier ValueType attributes
        if (secRef.containsKeyIdentifier()) {
            String valueType = secRef.getKeyIdentifierValueType();
            if (samlAssertion.getSaml1() != null
                && !WSConstants.WSS_SAML_KI_VALUE_TYPE.equals(valueType)) {
                bspEnforcer.handleBSPRule(BSPRule.R6603);
            }
            if (samlAssertion.getSaml2() != null
                && !WSConstants.WSS_SAML2_KI_VALUE_TYPE.equals(valueType)) {
                bspEnforcer.handleBSPRule(BSPRule.R6616);
            }
            String encoding = secRef.getKeyIdentifierEncodingType();
            if (encoding != null && !"".equals(encoding)) {
                bspEnforcer.handleBSPRule(BSPRule.R6604);
            }
        }
        
        // Check the TokenType attribute
        String tokenType = secRef.getTokenType();
        if (samlAssertion.getSaml1() != null && !WSConstants.WSS_SAML_TOKEN_TYPE.equals(tokenType)) {
            bspEnforcer.handleBSPRule(BSPRule.R6611);
        }
        if (samlAssertion.getSaml2() != null && !WSConstants.WSS_SAML2_TOKEN_TYPE.equals(tokenType)) {
            bspEnforcer.handleBSPRule(BSPRule.R6617);
        }
        
        // Check the ValueType attribute of the Reference for SAML2
        if (samlAssertion.getSaml2() != null && secRef.containsReference()) {
            String valueType = secRef.getReference().getValueType();
            if (valueType != null && !"".equals(valueType)) {
                bspEnforcer.handleBSPRule(BSPRule.R6614);
            }
        }
    }
    
    /**
     * Check that the Username token referenced by the SecurityTokenReference argument 
     * is BSP compliant.
     * @param secRef The SecurityTokenReference to the Username token
     * @param bspEnforcer a BSPEnforcer instance to enforce BSP rules
     * @throws WSSecurityException
     */
    public static void checkUsernameTokenBSPCompliance(
        SecurityTokenReference secRef, BSPEnforcer bspEnforcer
    ) throws WSSecurityException {
        if (!secRef.containsReference()) {
            // BSP does not permit using a KeyIdentifier to refer to a U/T
            bspEnforcer.handleBSPRule(BSPRule.R4215);
        }
        
        if (secRef.getReference() != null) {
            String valueType = secRef.getReference().getValueType();
            if (!WSConstants.WSS_USERNAME_TOKEN_VALUE_TYPE.equals(valueType)) {
                bspEnforcer.handleBSPRule(BSPRule.R4214);
            }
        }
    }

    /**
     * Get the Secret Key from a CallbackHandler
     * @param id The id of the element
     * @param type The type of the element (may be null)
     * @param cb The CallbackHandler object
     * @return A Secret Key
     * @throws WSSecurityException
     */
    public static byte[] getSecretKeyFromToken(
        String id,
        String type,
        int identifier,
        RequestData data
    ) throws WSSecurityException {
        String uri = XMLUtils.getIDFromReference(id);
        WSPasswordCallback pwcb = 
            new WSPasswordCallback(uri, null, type, identifier);
        try {
            Callback[] callbacks = new Callback[]{pwcb};
            if (data.getCallbackHandler() != null) {
                data.getCallbackHandler().handle(callbacks);
                return pwcb.getKey();
            }
        } catch (Exception e) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.FAILURE,
                "noPassword", e, uri);
        }

        return null;
    }
}
