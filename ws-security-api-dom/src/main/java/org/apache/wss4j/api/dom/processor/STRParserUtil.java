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

package org.apache.wss4j.api.dom.processor;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;

import org.apache.wss4j.common.bsp.BSPEnforcer;
import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.callback.CallbackLookup;
import org.apache.wss4j.api.dom.callback.DOMCallbackLookup;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.token.BinarySecurity;
import org.apache.wss4j.common.token.PKIPathSecurity;
import org.apache.wss4j.common.token.SecurityTokenReference;
import org.apache.wss4j.common.token.X509Security;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.api.dom.WSConstants;
import org.apache.wss4j.api.dom.WSDocInfo;
import org.apache.wss4j.api.dom.RequestData;
import org.apache.wss4j.api.dom.message.token.KerberosSecurity;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Some utilities for the STRParsers.
 */
public final class STRParserUtil {

    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(STRParserUtil.class);

    private STRParserUtil() {
        // complete
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
                        && !(valueType == null || valueType.length() == 0)
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
     * @param saml2Token If the STR refers to a SAML 2 token or not
     * @param bspEnforcer a BSPEnforcer instance to enforce BSP rules
     * @throws WSSecurityException
     */
    public static void checkSamlTokenBSPCompliance(
        SecurityTokenReference secRef,
        boolean saml2Token,
        BSPEnforcer bspEnforcer
    ) throws WSSecurityException {
        // Check the KeyIdentifier ValueType attributes
        if (secRef.containsKeyIdentifier()) {
            String valueType = secRef.getKeyIdentifierValueType();
            if (!saml2Token && !WSConstants.WSS_SAML_KI_VALUE_TYPE.equals(valueType)) {
                bspEnforcer.handleBSPRule(BSPRule.R6603);
            }
            if (saml2Token && !WSConstants.WSS_SAML2_KI_VALUE_TYPE.equals(valueType)) {
                bspEnforcer.handleBSPRule(BSPRule.R6616);
            }
            String encoding = secRef.getKeyIdentifierEncodingType();
            if (encoding != null && encoding.length() != 0) {
                bspEnforcer.handleBSPRule(BSPRule.R6604);
            }
        }

        // Check the TokenType attribute
        String tokenType = secRef.getTokenType();
        if (!saml2Token && !WSConstants.WSS_SAML_TOKEN_TYPE.equals(tokenType)) {
            bspEnforcer.handleBSPRule(BSPRule.R6611);
        }
        if (saml2Token && !WSConstants.WSS_SAML2_TOKEN_TYPE.equals(tokenType)) {
            bspEnforcer.handleBSPRule(BSPRule.R6617);
        }

        // Check the ValueType attribute of the Reference for SAML2
        if (saml2Token && secRef.containsReference()) {
            String valueType = secRef.getReference().getValueType();
            if (valueType != null && valueType.length() != 0) {
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
     * @param identifier The WSPasswordCallback usage identifier
     * @poaram data The RequestData Object
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
                WSSecurityException.ErrorCode.FAILURE, e,
                "noPassword", new Object[] {uri});
        }

        return new byte[0];
    }

    public static Element getTokenElement(
        Document doc, WSDocInfo docInfo, CallbackHandler cb,
        String uri, String valueType
    ) throws WSSecurityException {
        LOG.debug("Token reference uri: {}", uri);
        LOG.debug("Token reference ValueType: {}", valueType);

        if (uri == null) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.INVALID_SECURITY, "badReferenceURI"
            );
        }

        Element tokElement =
            findProcessedTokenElement(doc, docInfo, cb, uri, valueType);
        if (tokElement == null) {
            tokElement = findUnprocessedTokenElement(doc, docInfo, uri, valueType);
        }

        if (tokElement == null) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.SECURITY_TOKEN_UNAVAILABLE,
                "noToken", new Object[] {uri});
        }
        return tokElement;
    }

    /**
     * Find a token that has not been processed already - in other words, it searches for
     * the element, rather than trying to access previous results to find the element
     * @param doc Parent Document
     * @param docInfo WSDocInfo instance
     * @param uri URI of the element
     * @param type Type of the element
     * @return A DOM element
     * @throws WSSecurityException
     */
    public static Element findUnprocessedTokenElement(
        Document doc,
        WSDocInfo docInfo,
        String uri,
        String type
    ) throws WSSecurityException {
        String id = XMLUtils.getIDFromReference(uri);
        //
        // Delegate finding the element to the CallbackLookup instance
        //
        CallbackLookup callbackLookup = null;
        if (docInfo != null) {
            callbackLookup = docInfo.getCallbackLookup();
        }
        if (callbackLookup == null) {
            callbackLookup = new DOMCallbackLookup(doc);
        }
        return callbackLookup.getElement(id, type, true);
    }

    /**
     * Find a token that has been processed already - in other words, it access previous
     * results to find the element, rather than conducting a general search
     * @param doc Parent Document
     * @param docInfo WSDocInfo instance
     * @param cb CallbackHandler instance
     * @param uri URI of the element
     * @param type Type of the element
     * @return A DOM element
     * @throws WSSecurityException
     */
    public static Element findProcessedTokenElement(
        Document doc,
        WSDocInfo docInfo,
        CallbackHandler cb,
        String uri,
        String type
    ) throws WSSecurityException {
        String id = XMLUtils.getIDFromReference(uri);
        //
        // Try to find it from the WSDocInfo instance first
        //
        if (docInfo != null) {
            Element token = docInfo.getTokenElement(id);
            if (token != null) {
                return token;
            }
        }

        //
        // Try to find a custom token
        //
        if (cb != null && (WSConstants.WSC_SCT.equals(type)
            || WSConstants.WSC_SCT_05_12.equals(type)
            || WSConstants.WSS_SAML_KI_VALUE_TYPE.equals(type)
            || WSConstants.WSS_SAML2_KI_VALUE_TYPE.equals(type)
            || KerberosSecurity.isKerberosToken(type))) {
            //try to find a custom token
            WSPasswordCallback pwcb =
                new WSPasswordCallback(id, WSPasswordCallback.CUSTOM_TOKEN);
            try {
                cb.handle(new Callback[]{pwcb});
                Element assertionElem = pwcb.getCustomToken();
                if (assertionElem != null) {
                    return (Element)doc.importNode(assertionElem, true);
                }
            } catch (Exception e) {
                LOG.debug(e.getMessage(), e);
                // Consume this failure
            }
        }
        return null;
    }

}
