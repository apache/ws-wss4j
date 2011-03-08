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
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.message.token.DerivedKeyToken;
import org.apache.ws.security.message.token.Reference;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.saml.SAMLKeyInfo;
import org.apache.ws.security.saml.SAMLUtil;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Element;

import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Map;

import javax.security.auth.callback.Callback;

/**
 * This implementation of STRParser is for parsing a SecurityTokenReference element, found in the
 * KeyInfo element associated with an EncryptedData element.
 */
public class SecurityTokenRefSTRParser implements STRParser {
    
    /**
     * The Signature method. This is used when deriving a key.
     */
    public static final String SIGNATURE_METHOD = "signature_method";
    
    private byte[] secretKey;
    
    /**
     * Parse a SecurityTokenReference element and extract credentials.
     * 
     * @param strElement The SecurityTokenReference element
     * @param crypto The crypto instance used to extract credentials
     * @param cb The CallbackHandler instance to supply passwords
     * @param wsDocInfo The WSDocInfo object to access previous processing results
     * @param config The WSSConfig object used to access configuration
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
        WSSConfig config = data.getWssConfig();
        if (config != null) {
            bspCompliant = config.isWsiBSPCompliant();
        }
        
        SecurityTokenReference secRef = new SecurityTokenReference(strElement, bspCompliant);

        if (secRef.containsReference()) {
            Reference reference = secRef.getReference();
            String uri = reference.getURI();
            String id = uri;
            if (id.charAt(0) == '#') {
                id = id.substring(1);
            }
            WSSecurityEngineResult result = wsDocInfo.getResult(id);
            if (result != null) {
                int action = ((Integer)result.get(WSSecurityEngineResult.TAG_ACTION)).intValue();
                if (WSConstants.ENCR == action) {
                    if (bspCompliant) {
                        BSPEnforcer.checkEncryptedKeyBSPCompliance(secRef);
                    }
                    secretKey = (byte[])result.get(WSSecurityEngineResult.TAG_SECRET);
                } else if (WSConstants.DKT == action) {
                    DerivedKeyToken dkt = 
                        (DerivedKeyToken)result.get(WSSecurityEngineResult.TAG_DERIVED_KEY_TOKEN);
                    byte[] secret = 
                        (byte[])result.get(WSSecurityEngineResult.TAG_SECRET);
                    String algorithm = (String)parameters.get(SIGNATURE_METHOD);
                    secretKey = dkt.deriveKey(WSSecurityUtil.getKeyLength(algorithm), secret);
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
                } else if (WSConstants.SCT == action) {
                    secretKey = (byte[])result.get(WSSecurityEngineResult.TAG_SECRET);
                }
            } else {
                // Try asking the CallbackHandler for the secret key
                secretKey = getSecretKeyFromToken(id, null, data);
                if (secretKey == null) {
                    throw new WSSecurityException(
                            WSSecurityException.FAILED_CHECK, "unsupportedKeyId"
                    );
                }
            }
        } else if (secRef.containsKeyIdentifier()){
            String valueType = secRef.getKeyIdentifierValueType();
            if (WSConstants.WSS_SAML_KI_VALUE_TYPE.equals(valueType)
                || WSConstants.WSS_SAML2_KI_VALUE_TYPE.equals(valueType)) { 
                AssertionWrapper assertion = 
                    SAMLUtil.getAssertionFromKeyIdentifier(
                        secRef, strElement, 
                        data, wsDocInfo
                    );
                if (bspCompliant) {
                    BSPEnforcer.checkSamlTokenBSPCompliance(secRef, assertion);
                }
                SAMLKeyInfo samlKi = 
                    SAMLUtil.getCredentialFromSubject(assertion,
                                                      data,
                                                      wsDocInfo, bspCompliant);
                // TODO Handle malformed SAML tokens where they don't have the 
                // secret in them
                secretKey = samlKi.getSecret();
            } else {
                if (bspCompliant && SecurityTokenReference.ENC_KEY_SHA1_URI.equals(valueType)) {
                    BSPEnforcer.checkEncryptedKeyBSPCompliance(secRef);
                } 
                secretKey = 
                    getSecretKeyFromToken(
                        secRef.getKeyIdentifierValue(), secRef.getKeyIdentifierValueType(), 
                        data);
            }
        } else {
            throw new WSSecurityException(WSSecurityException.FAILED_CHECK, "noReference");
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
        RequestData data
    ) throws WSSecurityException {
        if (id.charAt(0) == '#') {
            id = id.substring(1);
        }
        WSPasswordCallback pwcb = 
            new WSPasswordCallback(id, null, type, WSPasswordCallback.SECRET_KEY, data);
        try {
            Callback[] callbacks = new Callback[]{pwcb};
            data.getCallbackHandler().handle(callbacks);
        } catch (Exception e) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE,
                "noPassword", 
                new Object[] {id}, 
                e
            );
        }

        return pwcb.getKey();
    }
    
    
}
