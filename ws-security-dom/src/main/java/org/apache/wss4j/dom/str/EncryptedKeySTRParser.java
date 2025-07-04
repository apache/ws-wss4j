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

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Optional;

import javax.xml.namespace.QName;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SAMLKeyInfo;
import org.apache.wss4j.api.dom.saml.SAMLKeyInfoProcessor;
import org.apache.wss4j.common.token.BinarySecurity;
import org.apache.wss4j.common.token.Reference;
import org.apache.wss4j.common.token.SecurityTokenReference;
import org.apache.wss4j.common.token.X509Security;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.api.dom.WSConstants;
import org.apache.wss4j.api.dom.WSDocInfo;
import org.apache.wss4j.api.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.api.dom.processor.STRParserUtil;
import org.apache.wss4j.api.dom.RequestData;
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
        if (parameters == null || parameters.getData() == null || parameters.getData().getWsDocInfo() == null
            || parameters.getStrElement() == null) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.FAILURE, "invalidSTRParserParameter"
            );
        }

        SecurityTokenReference secRef =
            new SecurityTokenReference(parameters.getStrElement(), parameters.getData().getBSPEnforcer());

        String uri = null;
        if (secRef.getReference() != null) {
            uri = secRef.getReference().getURI();
            uri = XMLUtils.getIDFromReference(uri);
        } else if (secRef.containsKeyIdentifier()) {
            uri = secRef.getKeyIdentifierValue();
        }

        WSSecurityEngineResult result = parameters.getData().getWsDocInfo().getResult(uri);
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

        Integer action = (Integer) result.get(WSSecurityEngineResult.TAG_ACTION);
        if (action != null && WSConstants.BST == action.intValue()) {
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
        } else if (action != null
            && (WSConstants.ST_UNSIGNED == action.intValue() || WSConstants.ST_SIGNED == action.intValue())) {
            // Check BSP compliance
            Element token = (Element)result.get(WSSecurityEngineResult.TAG_TOKEN_ELEMENT);
            boolean saml2Token = "urn:oasis:names:tc:SAML:2.0:assertion".equals(token.getNamespaceURI());
            STRParserUtil.checkSamlTokenBSPCompliance(secRef, saml2Token, data.getBSPEnforcer());

            // Get certificates and public key from the SAML assertion that was previously processed
            X509Certificate[] certs = (X509Certificate[])result.get(WSSecurityEngineResult.TAG_X509_CERTIFICATES);
            parserResult.setCerts(certs);
            PublicKey publicKey = (PublicKey)result.get(WSSecurityEngineResult.TAG_PUBLIC_KEY);
            parserResult.setPublicKey(publicKey);
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
        WSDocInfo wsDocInfo = data.getWsDocInfo();
        Crypto crypto = data.getDecCrypto();

        if (secRef.containsKeyIdentifier()) {
            if (WSConstants.WSS_SAML_KI_VALUE_TYPE.equals(secRef.getKeyIdentifierValueType())
                || WSConstants.WSS_SAML2_KI_VALUE_TYPE.equals(secRef.getKeyIdentifierValueType())) {
                Optional<SAMLKeyInfoProcessor> keyInfoProcessor = data.getWssConfig().getSAMLKeyInfoProcessor();
                if (keyInfoProcessor.isPresent()) {
                    SAMLKeyInfo samlKi = keyInfoProcessor.get().processSAMLKeyInfoFromSecurityTokenReference(secRef, data);
                    parserResult.setCerts(samlKi.getCerts());
                    parserResult.setPublicKey(samlKi.getPublicKey());
                }
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
            if (el.equals(WSConstants.BINARY_TOKEN)) {
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
