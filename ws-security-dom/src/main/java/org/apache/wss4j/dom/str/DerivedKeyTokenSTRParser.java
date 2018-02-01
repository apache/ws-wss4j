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
import java.util.Arrays;
import java.util.List;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SAMLKeyInfo;
import org.apache.wss4j.common.saml.SAMLUtil;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.token.BinarySecurity;
import org.apache.wss4j.common.token.SecurityTokenReference;
import org.apache.wss4j.common.util.KeyUtils;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.saml.WSSSAMLKeyInfoProcessor;

/**
 * This implementation of STRParser is for parsing a SecurityTokenReference element associated
 * with a DerivedKeyToken element.
 */
public class DerivedKeyTokenSTRParser implements STRParser {

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
        if (secRef.getReference() != null) {
            uri = secRef.getReference().getURI();
            uri = XMLUtils.getIDFromReference(uri);
        } else if (secRef.containsKeyIdentifier()) {
            uri = secRef.getKeyIdentifierValue();
        }

        WSSecurityEngineResult result = parameters.getWsDocInfo().getResult(uri);
        if (result != null) {
            return processPreviousResult(result, secRef, parameters);
        }

        return processSTR(secRef, uri, parameters);
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

        Integer action = (Integer)result.get(WSSecurityEngineResult.TAG_ACTION);
        if (action != null
            && (WSConstants.UT_NOPASSWORD == action.intValue() || WSConstants.UT == action.intValue())) {
            STRParserUtil.checkUsernameTokenBSPCompliance(secRef, data.getBSPEnforcer());
            byte[] secretKey = (byte[])result.get(WSSecurityEngineResult.TAG_SECRET);
            parserResult.setSecretKey(secretKey);
        } else if (action != null && WSConstants.ENCR == action.intValue()) {
            STRParserUtil.checkEncryptedKeyBSPCompliance(secRef, data.getBSPEnforcer());
            byte[] secretKey = (byte[])result.get(WSSecurityEngineResult.TAG_SECRET);
            parserResult.setSecretKey(secretKey);
        } else if (action != null && (WSConstants.SCT == action.intValue() || WSConstants.BST == action.intValue())) {
            byte[] secretKey = (byte[])result.get(WSSecurityEngineResult.TAG_SECRET);
            parserResult.setSecretKey(secretKey);
        } else if (action != null
            && (WSConstants.ST_UNSIGNED == action.intValue() || WSConstants.ST_SIGNED == action.intValue())) {
            SamlAssertionWrapper samlAssertion =
                (SamlAssertionWrapper)result.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
            STRParserUtil.checkSamlTokenBSPCompliance(secRef, samlAssertion, data.getBSPEnforcer());

            SAMLKeyInfo keyInfo =
                SAMLUtil.getCredentialFromSubject(samlAssertion,
                        new WSSSAMLKeyInfoProcessor(data, parameters.getWsDocInfo()),
                        data.getSigVerCrypto(), data.getCallbackHandler());
            // TODO Handle malformed SAML tokens where they don't have the
            // secret in them
            byte[] secretKey = keyInfo.getSecret();
            parserResult.setSecretKey(secretKey);
        } else {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.FAILED_CHECK, "unsupportedKeyId"
            );
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

        if (secRef.containsReference()) {
            // Now use the callback and get it
            byte[] secretKey =
                STRParserUtil.getSecretKeyFromToken(uri, null, WSPasswordCallback.SECURITY_CONTEXT_TOKEN, data);
            if (secretKey == null) {
                throw new WSSecurityException(
                    WSSecurityException.ErrorCode.FAILED_CHECK, "unsupportedKeyId",
                    new Object[] {uri});
            }
            parserResult.setSecretKey(secretKey);
        } else if (secRef.containsKeyIdentifier()) {
            String keyIdentifierValueType = secRef.getKeyIdentifierValueType();
            if (WSConstants.WSS_KRB_KI_VALUE_TYPE.equals(keyIdentifierValueType)) {
                byte[] secretKey =
                    STRParserUtil.getSecretKeyFromToken(
                        secRef.getKeyIdentifierValue(), keyIdentifierValueType,
                        WSPasswordCallback.SECRET_KEY, data
                    );
                if (secretKey == null) {
                    byte[] keyBytes = secRef.getSKIBytes();
                    List<WSSecurityEngineResult> resultsList =
                        parameters.getWsDocInfo().getResultsByTag(WSConstants.BST);
                    for (WSSecurityEngineResult bstResult : resultsList) {
                        BinarySecurity bstToken =
                            (BinarySecurity)bstResult.get(WSSecurityEngineResult.TAG_BINARY_SECURITY_TOKEN);
                        byte[] tokenDigest = KeyUtils.generateDigest(bstToken.getToken());
                        if (Arrays.equals(tokenDigest, keyBytes)) {
                            secretKey = (byte[])bstResult.get(WSSecurityEngineResult.TAG_SECRET);
                            break;
                        }
                    }
                }
                if (secretKey == null) {
                    throw new WSSecurityException(
                        WSSecurityException.ErrorCode.FAILED_CHECK, "unsupportedKeyId",
                        new Object[] {uri});
                }
                parserResult.setSecretKey(secretKey);
            } else {
                if (SecurityTokenReference.ENC_KEY_SHA1_URI.equals(keyIdentifierValueType)) {
                    STRParserUtil.checkEncryptedKeyBSPCompliance(secRef, data.getBSPEnforcer());
                }
                Crypto crypto = data.getDecCrypto();
                X509Certificate[] certs = secRef.getKeyIdentifier(crypto);
                if (certs == null || certs.length < 1 || certs[0] == null) {
                    byte[] secretKey =
                        STRParserUtil.getSecretKeyFromToken(
                            secRef.getKeyIdentifierValue(), keyIdentifierValueType,
                            WSPasswordCallback.SECRET_KEY, data
                       );
                    if (secretKey == null) {
                        throw new WSSecurityException(
                            WSSecurityException.ErrorCode.FAILED_CHECK, "unsupportedKeyId",
                            new Object[] {uri});
                    }
                    parserResult.setSecretKey(secretKey);
                } else {
                    byte[] secretKey = crypto.getPrivateKey(certs[0], data.getCallbackHandler()).getEncoded();
                    parserResult.setSecretKey(secretKey);
                }
            }
        } else {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.FAILED_CHECK, "unsupportedKeyId"
            );
        }

        return parserResult;
    }

}
