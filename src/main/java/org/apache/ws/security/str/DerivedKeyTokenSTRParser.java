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
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.message.token.Reference;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.message.token.UsernameToken;
import org.apache.ws.security.saml.SAMLKeyInfo;
import org.apache.ws.security.saml.SAMLUtil;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.w3c.dom.Element;

import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;

/**
 * This implementation of STRParser is for parsing a SecurityTokenReference element associated
 * with a DerivedKeyToken element.
 */
public class DerivedKeyTokenSTRParser implements STRParser {
    
    private byte[] secretKey;
    
    private boolean bspCompliant = true;
    
    /**
     * Set whether we should process tokens according to the BSP spec
     * @param bspCompliant whether we should process tokens according to the BSP spec
     */
    public void setBspCompliant(boolean bspCompliant) {
        this.bspCompliant = bspCompliant;
    }
    
    /**
     * Parse a SecurityTokenReference element and extract credentials.
     * 
     * @param strElement The SecurityTokenReference element
     * @param crypto The crypto instance used to extract credentials
     * @param cb The CallbackHandler instance to supply passwords
     * @param wsDocInfo The WSDocInfo object to access previous processing results
     * @param parameters A set of implementation-specific parameters
     * @throws WSSecurityException
     */
    public void parseSecurityTokenReference(
        Element strElement,
        Crypto crypto,
        CallbackHandler cb,
        WSDocInfo wsDocInfo,
        Map<String, Object> parameters
    ) throws WSSecurityException {
        SecurityTokenReference secRef = new SecurityTokenReference(strElement, bspCompliant);
        
        String uri = null;
        String keyIdentifierValueType = null;
        String keyIdentifierValue = null;
        
        WSSecurityEngineResult result = null;
        if (secRef.containsReference()) {
            Reference ref = secRef.getReference();
            uri = ref.getURI();
            if (uri.charAt(0) == '#') {
                uri = uri.substring(1);
            }
            result = wsDocInfo.getResult(uri);
        } else {
            // Contains key identifier
            keyIdentifierValue = secRef.getKeyIdentifierValue();
            keyIdentifierValueType = secRef.getKeyIdentifierValueType();
            result = wsDocInfo.getResult(keyIdentifierValue);
        }
        
        if (result != null) {
            int action = ((Integer)result.get(WSSecurityEngineResult.TAG_ACTION)).intValue();
            if (WSConstants.UT_NOPASSWORD == action || WSConstants.UT == action) {
                if (bspCompliant) {
                    checkUTBSPCompliance(secRef);
                }
                UsernameToken usernameToken = 
                    (UsernameToken)result.get(WSSecurityEngineResult.TAG_USERNAME_TOKEN);
                usernameToken.setRawPassword(cb);
                secretKey = usernameToken.getDerivedKey();
            } else if (WSConstants.ENCR == action) {
                secretKey = (byte[])result.get(WSSecurityEngineResult.TAG_SECRET);
            } else if (WSConstants.SCT == action) {
                secretKey = (byte[])result.get(WSSecurityEngineResult.TAG_SECRET);
            } else if (WSConstants.ST_UNSIGNED == action || WSConstants.ST_SIGNED == action) {
                AssertionWrapper assertion = 
                    (AssertionWrapper)result.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
                SAMLKeyInfo keyInfo = 
                    SAMLUtil.getCredentialFromSubject(assertion, crypto, cb, wsDocInfo, bspCompliant);
                // TODO Handle malformed SAML tokens where they don't have the 
                // secret in them
                secretKey = keyInfo.getSecret();
            } else {
                throw new WSSecurityException(
                    WSSecurityException.FAILED_CHECK, "unsupportedKeyId"
                );
            }
        } else if (result == null && uri != null) {
            // Now use the callback and get it
            secretKey = 
                getSecretKeyFromToken(uri, null, WSPasswordCallback.SECURITY_CONTEXT_TOKEN, cb);
        } else if (keyIdentifierValue != null && keyIdentifierValueType != null) {
            X509Certificate[] certs = secRef.getKeyIdentifier(crypto);
            if (certs == null || certs.length < 1 || certs[0] == null) {
                secretKey = 
                    this.getSecretKeyFromToken(
                        keyIdentifierValue, keyIdentifierValueType, 
                        WSPasswordCallback.SECRET_KEY, cb
                   ); 
            } else {
                secretKey = crypto.getPrivateKey(certs[0], cb).getEncoded();
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
     * Check the BSP compliance for a reference to a UsernameToken
     * @param secRef the SecurityTokenReference element
     * @throws WSSecurityException
     */
    private void checkUTBSPCompliance(SecurityTokenReference secRef) throws WSSecurityException {
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
        CallbackHandler cb
    ) throws WSSecurityException {
        if (id.charAt(0) == '#') {
            id = id.substring(1);
        }
        WSPasswordCallback pwcb = 
            new WSPasswordCallback(id, null, type, identifier);
        try {
            Callback[] callbacks = new Callback[]{pwcb};
            cb.handle(callbacks);
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
