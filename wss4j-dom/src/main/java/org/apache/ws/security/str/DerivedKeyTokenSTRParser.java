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
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.message.token.BinarySecurity;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.saml.SAMLKeyInfo;
import org.apache.ws.security.saml.SAMLUtil;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Element;

import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import javax.security.auth.callback.Callback;

/**
 * This implementation of STRParser is for parsing a SecurityTokenReference element associated
 * with a DerivedKeyToken element.
 */
public class DerivedKeyTokenSTRParser implements STRParser {
    
    private byte[] secretKey;
    
    /**
     * Parse a SecurityTokenReference element and extract credentials.
     * 
     * @param strElement The SecurityTokenReference element
     * @param data the RequestData associated with the request
     * @param wsDocInfo The WSDocInfo object to access previous processing results
     * @param parameters A set of implementation-specific parameters
     * @throws WSSecurityException
     */
    public void parseSecurityTokenReference(
        Element strElement,
        RequestData data,
        WSDocInfo wsDocInfo,
        Map<String, Object> parameters
    ) throws WSSecurityException {
        boolean bspCompliant = true;
        Crypto crypto = data.getDecCrypto();
        WSSConfig config = data.getWssConfig();

        if (config != null) {
            bspCompliant = config.isWsiBSPCompliant();
        }
        
        SecurityTokenReference secRef = new SecurityTokenReference(strElement, bspCompliant);
        
        String uri = null;
        if (secRef.containsReference()) {
            uri = secRef.getReference().getURI();
            if (uri.charAt(0) == '#') {
                uri = uri.substring(1);
            }
        } else if (secRef.containsKeyIdentifier()) {
            uri = secRef.getKeyIdentifierValue();
        }
        
        WSSecurityEngineResult result = wsDocInfo.getResult(uri);
        if (result != null) {
            processPreviousResult(result, secRef, data, wsDocInfo, bspCompliant);
        } else if (secRef.containsReference()) { 
            // Now use the callback and get it
            secretKey = 
                getSecretKeyFromToken(uri, null, WSPasswordCallback.SECURITY_CONTEXT_TOKEN, data);
            if (secretKey == null) {
                throw new WSSecurityException(
                    WSSecurityException.FAILED_CHECK, "unsupportedKeyId", new Object[] {uri}
                );
            }
        } else if (secRef.containsKeyIdentifier()) {
            String keyIdentifierValueType = secRef.getKeyIdentifierValueType();
            if (WSConstants.WSS_KRB_KI_VALUE_TYPE.equals(keyIdentifierValueType)) {
                secretKey = 
                    getSecretKeyFromToken(
                        secRef.getKeyIdentifierValue(), keyIdentifierValueType, 
                        WSPasswordCallback.SECRET_KEY, data
                    );
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
                        WSSecurityException.FAILED_CHECK, "unsupportedKeyId", new Object[] {uri}
                    );
                }
            } else {
                if (bspCompliant 
                    && keyIdentifierValueType.equals(SecurityTokenReference.ENC_KEY_SHA1_URI)) {
                    BSPEnforcer.checkEncryptedKeyBSPCompliance(secRef);
                }
                X509Certificate[] certs = secRef.getKeyIdentifier(crypto);
                if (certs == null || certs.length < 1 || certs[0] == null) {
                    secretKey = 
                        this.getSecretKeyFromToken(
                            secRef.getKeyIdentifierValue(), keyIdentifierValueType, 
                            WSPasswordCallback.SECRET_KEY, data
                       ); 
                    if (secretKey == null) {
                        throw new WSSecurityException(
                            WSSecurityException.FAILED_CHECK, "unsupportedKeyId", new Object[] {uri}
                        );
                    }
                } else {
                    secretKey = crypto.getPrivateKey(certs[0], data.getCallbackHandler()).getEncoded();
                }
            }
        } else {
            throw new WSSecurityException(
                WSSecurityException.FAILED_CHECK, "unsupportedKeyId"
            );
        }
    }
    
    /**
     * Get the X509Certificates associated with this SecurityTokenReference
     * @return the X509Certificates associated with this SecurityTokenReference
     */
    public X509Certificate[] getCertificates() {
        return null;
    }
    
    /**
     * Get the Principal associated with this SecurityTokenReference
     * @return the Principal associated with this SecurityTokenReference
     */
    public Principal getPrincipal() {
        return null;
    }
    
    /**
     * Get the PublicKey associated with this SecurityTokenReference
     * @return the PublicKey associated with this SecurityTokenReference
     */
    public PublicKey getPublicKey() {
        return null;
    }
    
    /**
     * Get the Secret Key associated with this SecurityTokenReference
     * @return the Secret Key associated with this SecurityTokenReference
     */
    public byte[] getSecretKey() {
        return secretKey;
    }
    
    /**
     * Get whether the returned credential is already trusted or not. This is currently
     * applicable in the case of a credential extracted from a trusted HOK SAML Assertion,
     * and a BinarySecurityToken that has been processed by a Validator. In these cases,
     * the SignatureProcessor does not need to verify trust on the credential.
     * @return true if trust has already been verified on the returned Credential
     */
    public boolean isTrustedCredential() {
        return false;
    }
    
    /**
     * Get how the certificates were referenced
     * @return how the certificates were referenced
     */
    public REFERENCE_TYPE getCertificatesReferenceType() {
        return null;
    }

    /**
     * Get the Secret Key from a CallbackHandler
     * @param id The id of the element
     * @param type The type of the element (may be null)
     * @param cb The CallbackHandler object
     * @return A Secret Key
     * @throws WSSecurityException
     */
    private byte[] getSecretKeyFromToken(
        String id,
        String type,
        int identifier,
        RequestData data
    ) throws WSSecurityException {
        if (id.charAt(0) == '#') {
            id = id.substring(1);
        }
        WSPasswordCallback pwcb = 
            new WSPasswordCallback(id, null, type, identifier, data);
        try {
            Callback[] callbacks = new Callback[]{pwcb};
            if (data.getCallbackHandler() != null) {
                data.getCallbackHandler().handle(callbacks);
                return pwcb.getKey();
            }
        } catch (Exception e) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE,
                "noPassword", 
                new Object[] {id}, 
                e
            );
        }

        return null;
    }
    
    /**
     * Process a previous security result
     */
    private void processPreviousResult(
        WSSecurityEngineResult result,
        SecurityTokenReference secRef,
        RequestData data,
        WSDocInfo wsDocInfo,
        boolean bspCompliant
    ) throws WSSecurityException {
        int action = ((Integer)result.get(WSSecurityEngineResult.TAG_ACTION)).intValue();
        if (WSConstants.UT_NOPASSWORD == action || WSConstants.UT == action) {
            if (bspCompliant) {
                BSPEnforcer.checkUsernameTokenBSPCompliance(secRef);
            }
            secretKey = (byte[])result.get(WSSecurityEngineResult.TAG_SECRET);
        } else if (WSConstants.ENCR == action) {
            if (bspCompliant) {
                BSPEnforcer.checkEncryptedKeyBSPCompliance(secRef);
            }
            secretKey = (byte[])result.get(WSSecurityEngineResult.TAG_SECRET);
        } else if (WSConstants.SCT == action || WSConstants.BST == action) {
            secretKey = (byte[])result.get(WSSecurityEngineResult.TAG_SECRET);
        } else if (WSConstants.ST_UNSIGNED == action || WSConstants.ST_SIGNED == action) {
            AssertionWrapper assertion = 
                (AssertionWrapper)result.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
            if (bspCompliant) {
                BSPEnforcer.checkSamlTokenBSPCompliance(secRef, assertion);
            }
            SAMLKeyInfo keyInfo = 
                SAMLUtil.getCredentialFromSubject(assertion, 
                                                  data, wsDocInfo, bspCompliant);
            // TODO Handle malformed SAML tokens where they don't have the 
            // secret in them
            secretKey = keyInfo.getSecret();
        } else {
            throw new WSSecurityException(
                WSSecurityException.FAILED_CHECK, "unsupportedKeyId"
            );
        }
    }
}
