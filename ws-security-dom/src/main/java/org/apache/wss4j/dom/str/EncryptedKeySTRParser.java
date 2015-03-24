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

import java.security.cert.X509Certificate;

import javax.xml.namespace.QName;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SAMLKeyInfo;
import org.apache.wss4j.common.saml.SAMLUtil;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.token.BinarySecurity;
import org.apache.wss4j.common.token.Reference;
import org.apache.wss4j.common.token.SecurityTokenReference;
import org.apache.wss4j.common.token.X509Security;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSDocInfo;
import org.apache.wss4j.dom.WSSecurityEngine;
import org.apache.wss4j.dom.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.saml.WSSSAMLKeyInfoProcessor;
import org.w3c.dom.Element;

/**
 * This implementation of STRParser is for parsing a SecurityTokenReference element, found in the
 * KeyInfo element associated with an EncryptedKey element
 */
public class EncryptedKeySTRParser implements STRParser {
    
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
            return processPreviousResult(result, secRef, parameters);
        }
        
        return processSTR(secRef, parameters);
    }
    
    /**
     * Process a previous security result
     */
    private STRParserResult processPreviousResult(
        WSSecurityEngineResult result,
        SecurityTokenReference secRef,
        STRParserParameters parameters
    ) throws WSSecurityException {
        STRParserResult parserResult = new STRParserResult();
        RequestData data = parameters.getData();
        
        int action = (Integer) result.get(WSSecurityEngineResult.TAG_ACTION);
        if (WSConstants.BST == action) {
            BinarySecurity token = 
                (BinarySecurity)result.get(
                    WSSecurityEngineResult.TAG_BINARY_SECURITY_TOKEN
                );
            STRParserUtil.checkBinarySecurityBSPCompliance(secRef, token, data.getBSPEnforcer());
            X509Certificate[] certs = 
                (X509Certificate[])result.get(
                    WSSecurityEngineResult.TAG_X509_CERTIFICATES
                );
            parserResult.setCerts(certs);
        } else if (WSConstants.ST_UNSIGNED == action || WSConstants.ST_SIGNED == action) {
            SamlAssertionWrapper samlAssertion =
                (SamlAssertionWrapper)result.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
            STRParserUtil.checkSamlTokenBSPCompliance(secRef, samlAssertion, data.getBSPEnforcer());
          
            SAMLKeyInfo keyInfo = 
                SAMLUtil.getCredentialFromSubject(samlAssertion,
                        new WSSSAMLKeyInfoProcessor(data, parameters.getWsDocInfo()), 
                        data.getSigVerCrypto(), data.getCallbackHandler());
            parserResult.setCerts(keyInfo.getCerts());
        } else {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.UNSUPPORTED_SECURITY_TOKEN,
                "unsupportedBinaryTokenType"
            );
        }
        
        REFERENCE_TYPE referenceType = getReferenceType(secRef);
        if (referenceType != null) {
            parserResult.setReferenceType(referenceType);
        }
        return parserResult;
    }
    
    private STRParserResult processSTR(
        SecurityTokenReference secRef, STRParserParameters parameters
    ) throws WSSecurityException {
        STRParserResult parserResult = new STRParserResult();
        RequestData data = parameters.getData();
        Element strElement = parameters.getStrElement();
        WSDocInfo wsDocInfo = parameters.getWsDocInfo();
        Crypto crypto = data.getDecCrypto();
        
        if (secRef.containsKeyIdentifier()) {
            if (WSConstants.WSS_SAML_KI_VALUE_TYPE.equals(secRef.getKeyIdentifierValueType())
                || WSConstants.WSS_SAML2_KI_VALUE_TYPE.equals(secRef.getKeyIdentifierValueType())) {
                SamlAssertionWrapper samlAssertion =
                    STRParserUtil.getAssertionFromKeyIdentifier(
                        secRef, strElement, data, wsDocInfo
                    );
                STRParserUtil.checkSamlTokenBSPCompliance(secRef, samlAssertion, data.getBSPEnforcer());
                
                SAMLKeyInfo samlKi = 
                    SAMLUtil.getCredentialFromSubject(samlAssertion,
                            new WSSSAMLKeyInfoProcessor(data, wsDocInfo), 
                            data.getSigVerCrypto(), data.getCallbackHandler());
                parserResult.setCerts(samlKi.getCerts());
            } else {
                STRParserUtil.checkBinarySecurityBSPCompliance(secRef, null, data.getBSPEnforcer());
                parserResult.setCerts(secRef.getKeyIdentifier(crypto));
            }
        } else if (secRef.containsX509Data() || secRef.containsX509IssuerSerial()) {
            parserResult.setReferenceType(REFERENCE_TYPE.ISSUER_SERIAL);
            parserResult.setCerts(secRef.getX509IssuerSerial(crypto));
        } else if (secRef.containsReference()) {
            Reference reference = secRef.getReference();
            Element bstElement = 
                STRParserUtil.getTokenElement(strElement.getOwnerDocument(), wsDocInfo, data.getCallbackHandler(),
                                              reference.getURI(), reference.getValueType());

            // at this point ... check token type: Binary
            QName el = new QName(bstElement.getNamespaceURI(), bstElement.getLocalName());
            if (el.equals(WSSecurityEngine.BINARY_TOKEN)) {
                X509Security token = new X509Security(bstElement, data.getBSPEnforcer());
                STRParserUtil.checkBinarySecurityBSPCompliance(secRef, token, data.getBSPEnforcer());
                parserResult.setCerts(new X509Certificate[]{token.getX509Certificate(crypto)});
            } else {
                throw new WSSecurityException(
                    WSSecurityException.ErrorCode.UNSUPPORTED_SECURITY_TOKEN,
                    "unsupportedBinaryTokenType"
                );
            }
        } 

        REFERENCE_TYPE referenceType = getReferenceType(secRef);
        if (referenceType != null) {
            parserResult.setReferenceType(referenceType);
        }
        
        return parserResult;
    }
    
    private REFERENCE_TYPE getReferenceType(SecurityTokenReference secRef) {
        if (secRef.containsReference()) {
            return REFERENCE_TYPE.DIRECT_REF;
        } else if (secRef.containsKeyIdentifier()) {
            if (SecurityTokenReference.THUMB_URI.equals(secRef.getKeyIdentifierValueType())) {
                return REFERENCE_TYPE.THUMBPRINT_SHA1;
            } else {
                return REFERENCE_TYPE.KEY_IDENTIFIER;
            }
        }
        
        return null;
    }
}
