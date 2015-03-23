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

import java.util.Arrays;
import java.util.List;

import javax.xml.namespace.QName;

import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.saml.SAMLKeyInfo;
import org.apache.wss4j.common.saml.SAMLUtil;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSDocInfo;
import org.apache.wss4j.dom.WSSecurityEngine;
import org.apache.wss4j.dom.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.message.token.BinarySecurity;
import org.apache.wss4j.dom.message.token.DerivedKeyToken;
import org.apache.wss4j.dom.message.token.Reference;
import org.apache.wss4j.dom.message.token.SecurityTokenReference;
import org.apache.wss4j.dom.message.token.UsernameToken;
import org.apache.wss4j.dom.processor.Processor;
import org.apache.wss4j.dom.saml.WSSSAMLKeyInfoProcessor;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.w3c.dom.Element;

/**
 * This implementation of STRParser is for parsing a SecurityTokenReference element, found in the
 * KeyInfo element associated with an EncryptedData element.
 */
public class SecurityTokenRefSTRParser implements STRParser {
    
    /**
     * Parse a SecurityTokenReference element and extract credentials.
     * 
     * @param parameters The parameters to parse
     * @return the STRParserResult Object containing the parsing results
     * @throws WSSecurityException
     */
    public STRParserResult parseSecurityTokenReference(STRParserParameters parameters) throws WSSecurityException {
        
        if (parameters == null || parameters.getData() == null || parameters.getWsDocInfo() == null
            || parameters.getStrElement() == null) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.FAILURE, "invalidSTRParserParameter"
            );
        }
        
        SecurityTokenReference secRef = 
            new SecurityTokenReference(parameters.getStrElement(), parameters.getData().getBSPEnforcer());
        
        String uri = null;
        if (secRef.containsReference()) {
            uri = secRef.getReference().getURI();
            uri = XMLUtils.getIDFromReference(uri);
        } else if (secRef.containsKeyIdentifier()) {
            uri = secRef.getKeyIdentifierValue();
        }
        
        WSSecurityEngineResult result = parameters.getWsDocInfo().getResult(uri);
        if (result != null) {
            return processPreviousResult(result, secRef, uri, parameters);
        }
            
        return processSTR(secRef, uri, parameters);
    }
    
    /**
     * Get a SecretKey from a SAML Assertion
     */
    private byte[] getSecretKeyFromAssertion(
        SamlAssertionWrapper samlAssertion,
        SecurityTokenReference secRef,
        RequestData data,
        WSDocInfo wsDocInfo
    ) throws WSSecurityException {
        STRParserUtil.checkSamlTokenBSPCompliance(secRef, samlAssertion, data.getBSPEnforcer());
        SAMLKeyInfo samlKi = 
            SAMLUtil.getCredentialFromSubject(samlAssertion,
                    new WSSSAMLKeyInfoProcessor(data, wsDocInfo), 
                    data.getSigVerCrypto(), data.getCallbackHandler());
        if (samlKi == null) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.FAILED_CHECK, "invalidSAMLToken", "No Secret Key");
        }
        return samlKi.getSecret();
    }
    
    /**
     * Process a previous security result
     */
    private STRParserResult processPreviousResult(
        WSSecurityEngineResult result,
        SecurityTokenReference secRef,
        String uri,
        STRParserParameters parameters
    ) throws WSSecurityException {
        STRParserResult parserResult = new STRParserResult();
        RequestData data = parameters.getData();
        
        int action = (Integer) result.get(WSSecurityEngineResult.TAG_ACTION);
        if (WSConstants.ENCR == action) {
            STRParserUtil.checkEncryptedKeyBSPCompliance(secRef, data.getBSPEnforcer());
            byte[] secretKey = (byte[])result.get(WSSecurityEngineResult.TAG_SECRET);
            parserResult.setSecretKey(secretKey);
        } else if (WSConstants.DKT == action) {
            DerivedKeyToken dkt = 
                (DerivedKeyToken)result.get(WSSecurityEngineResult.TAG_DERIVED_KEY_TOKEN);
            byte[] secret = 
                (byte[])result.get(WSSecurityEngineResult.TAG_SECRET);
            byte[] secretKey = dkt.deriveKey(parameters.getDerivationKeyLength(), secret);
            parserResult.setSecretKey(secretKey);
            parserResult.setPrincipal(dkt.createPrincipal());
        } else if (WSConstants.ST_UNSIGNED == action || WSConstants.ST_SIGNED == action) {
            SamlAssertionWrapper samlAssertion =
                (SamlAssertionWrapper)result.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
            byte[] secretKey = 
                getSecretKeyFromAssertion(samlAssertion, secRef, data, parameters.getWsDocInfo());
            parserResult.setSecretKey(secretKey);
        } else if (WSConstants.SCT == action || WSConstants.BST == action) {
            byte[] secretKey = (byte[])result.get(WSSecurityEngineResult.TAG_SECRET);
            parserResult.setSecretKey(secretKey);
        } else if (WSConstants.UT_NOPASSWORD == action || WSConstants.UT == action) {
            STRParserUtil.checkUsernameTokenBSPCompliance(secRef, data.getBSPEnforcer());
            UsernameToken usernameToken = 
                (UsernameToken)result.get(WSSecurityEngineResult.TAG_USERNAME_TOKEN);

            usernameToken.setRawPassword(data);
            byte[] secretKey = usernameToken.getDerivedKey(data.getBSPEnforcer());
            parserResult.setSecretKey(secretKey);
        }
        
        if (parserResult.getSecretKey() == null) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.FAILED_CHECK, "unsupportedKeyId", uri);
        }
        
        return parserResult;
    }
    
    private STRParserResult processSTR(
        SecurityTokenReference secRef,
        String uri,
        STRParserParameters parameters
    ) throws WSSecurityException {
        STRParserResult parserResult = new STRParserResult();
        RequestData data = parameters.getData();
        Element strElement = parameters.getStrElement();
        WSDocInfo wsDocInfo = parameters.getWsDocInfo();

        if (secRef.containsReference()) {
            Reference reference = secRef.getReference();
            // Try asking the CallbackHandler for the secret key
            byte[] secretKey = 
                STRParserUtil.getSecretKeyFromToken(uri, reference.getValueType(), 
                                                    WSPasswordCallback.SECRET_KEY, data);
            if (secretKey == null) {
                Element token = 
                    secRef.getTokenElement(strElement.getOwnerDocument(), wsDocInfo, data.getCallbackHandler());
                QName el = new QName(token.getNamespaceURI(), token.getLocalName());
                if (el.equals(WSSecurityEngine.BINARY_TOKEN)) {
                    Processor proc = data.getWssConfig().getProcessor(WSSecurityEngine.BINARY_TOKEN);
                    List<WSSecurityEngineResult> bstResult =
                            proc.handleToken(token, data, wsDocInfo);
                    BinarySecurity bstToken = 
                            (BinarySecurity)bstResult.get(0).get(WSSecurityEngineResult.TAG_BINARY_SECURITY_TOKEN);
                    STRParserUtil.checkBinarySecurityBSPCompliance(secRef, bstToken, data.getBSPEnforcer());
                    secretKey = (byte[])bstResult.get(0).get(WSSecurityEngineResult.TAG_SECRET);
                } 
            }
            if (secretKey == null) {
                throw new WSSecurityException(
                    WSSecurityException.ErrorCode.FAILED_CHECK, "unsupportedKeyId", uri);
            }
            parserResult.setSecretKey(secretKey);
        } else if (secRef.containsKeyIdentifier()) {
            String valueType = secRef.getKeyIdentifierValueType();
            if (WSConstants.WSS_SAML_KI_VALUE_TYPE.equals(valueType)
                || WSConstants.WSS_SAML2_KI_VALUE_TYPE.equals(valueType)) {
                byte[] secretKey = 
                    STRParserUtil.getSecretKeyFromToken(secRef.getKeyIdentifierValue(), valueType, 
                                                        WSPasswordCallback.SECRET_KEY, data);
                if (secretKey == null) {
                    SamlAssertionWrapper samlAssertion =
                        STRParserUtil.getAssertionFromKeyIdentifier(
                            secRef, strElement, 
                            data, wsDocInfo
                        );
                    secretKey = getSecretKeyFromAssertion(samlAssertion, secRef, data, wsDocInfo);
                }
                parserResult.setSecretKey(secretKey);
            } else if (WSConstants.WSS_KRB_KI_VALUE_TYPE.equals(valueType)) {
                byte[] secretKey = 
                    STRParserUtil.getSecretKeyFromToken(secRef.getKeyIdentifierValue(), valueType, 
                                                        WSPasswordCallback.SECRET_KEY, data);
                if (secretKey == null) {
                    byte[] keyBytes = secRef.getSKIBytes();
                    List<WSSecurityEngineResult> resultsList = 
                        wsDocInfo.getResultsByTag(WSConstants.BST);
                    for (WSSecurityEngineResult bstResult : resultsList) {
                        BinarySecurity bstToken = 
                            (BinarySecurity)bstResult.get(WSSecurityEngineResult.TAG_BINARY_SECURITY_TOKEN);
                        byte[] tokenDigest = WSSecurityUtil.generateDigest(bstToken.getToken());
                        if (Arrays.equals(tokenDigest, keyBytes)) {
                            secretKey = (byte[])bstResult.get(WSSecurityEngineResult.TAG_SECRET);
                            break;
                        }
                    }
                }
                if (secretKey == null) {
                    throw new WSSecurityException(
                        WSSecurityException.ErrorCode.FAILED_CHECK, "unsupportedKeyId", uri);
                }
                parserResult.setSecretKey(secretKey);
            } else {
                if (SecurityTokenReference.ENC_KEY_SHA1_URI.equals(valueType)) {
                    STRParserUtil.checkEncryptedKeyBSPCompliance(secRef, data.getBSPEnforcer());
                } 
                byte[] secretKey = 
                    STRParserUtil.getSecretKeyFromToken(
                        secRef.getKeyIdentifierValue(), secRef.getKeyIdentifierValueType(), 
                        WSPasswordCallback.SECRET_KEY, data
                    );
                if (secretKey == null) {
                    throw new WSSecurityException(
                        WSSecurityException.ErrorCode.FAILED_CHECK, "unsupportedKeyId", uri);
                }
                parserResult.setSecretKey(secretKey);
            }
        } else {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, "noReference");
        }
        
        return parserResult;
    }
    
}
