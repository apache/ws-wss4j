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

import java.io.IOException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

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
        SecurityTokenReference secRef = new SecurityTokenReference(strElement);
        
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
            if (WSConstants.UT == action) {
                UsernameToken usernameToken = 
                    (UsernameToken)result.get(WSSecurityEngineResult.TAG_USERNAME_TOKEN);
                secretKey = usernameToken.getDerivedKey();
            } else if (WSConstants.ENCR == action) {
                secretKey = (byte[])result.get(WSSecurityEngineResult.TAG_SECRET);
            } else if (WSConstants.SCT == action) {
                secretKey = (byte[])result.get(WSSecurityEngineResult.TAG_SECRET);
            } else if (WSConstants.ST_UNSIGNED == action || WSConstants.ST_SIGNED == action) {
                AssertionWrapper assertion = 
                    (AssertionWrapper)result.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
                SAMLKeyInfo keyInfo = 
                    SAMLUtil.getCredentialFromSubject(assertion, crypto, cb);
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
            secretKey = getSecret(cb, uri);
        } else if (keyIdentifierValue != null && keyIdentifierValueType != null) {
            X509Certificate[] certs = secRef.getKeyIdentifier(crypto);
            if (certs == null || certs.length < 1 || certs[0] == null) {
                secretKey = this.getSecret(cb, keyIdentifierValue, keyIdentifierValueType); 
            } else {
                secretKey = this.getSecret(cb, crypto, certs);
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

    private byte[] getSecret(CallbackHandler cb, String id) throws WSSecurityException {
        if (cb == null) {
            throw new WSSecurityException(WSSecurityException.FAILURE, "noCallback");
        }

        WSPasswordCallback callback = 
            new WSPasswordCallback(id, WSPasswordCallback.SECURITY_CONTEXT_TOKEN);
        try {
            Callback[] callbacks = new Callback[]{callback};
            cb.handle(callbacks);
        } catch (IOException e) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE, 
                "noKey",
                new Object[] {id}, 
                e
            );
        } catch (UnsupportedCallbackException e) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE,
                "noKey",
                new Object[] {id}, 
                e
            );
        }

        return callback.getKey();
    }
    
    private byte[] getSecret(
        CallbackHandler cb, 
        String keyIdentifierValue, 
        String keyIdentifierType
    ) throws WSSecurityException {
        if (cb == null) {
            throw new WSSecurityException(WSSecurityException.FAILURE, "noCallback");
        }
        
        WSPasswordCallback pwcb = 
            new WSPasswordCallback(
                keyIdentifierValue, null, keyIdentifierType, WSPasswordCallback.ENCRYPTED_KEY_TOKEN
            );
        try {
            Callback[] callbacks = new Callback[]{pwcb};
            cb.handle(callbacks);
        } catch (IOException e) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE, 
                "noKey",
                new Object[] {keyIdentifierValue}, 
                e
            );
        } catch (UnsupportedCallbackException e) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE, 
                "noKey",
                new Object[] {keyIdentifierValue}, 
                e
            );
        }
            
        return pwcb.getKey();
    }
    
    private byte[] getSecret(
        CallbackHandler cb,
        Crypto crypto,
        X509Certificate certs[]
    ) throws WSSecurityException {
        if (cb == null) {
            throw new WSSecurityException(WSSecurityException.FAILURE, "noCallback");
        }

        String alias = crypto.getAliasForX509Cert(certs[0]);

        WSPasswordCallback pwCb = 
            new WSPasswordCallback(alias, WSPasswordCallback.DECRYPT);
        try {
            Callback[] callbacks = new Callback[]{pwCb};
            cb.handle(callbacks);
        } catch (IOException e) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE,
                "noPassword",
                new Object[]{alias}, 
                e
            );
        } catch (UnsupportedCallbackException e) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE,
                "noPassword",
                new Object[]{alias}, 
                e
            );
        }

        String password = pwCb.getPassword();
        if (password == null) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE, "noPassword", new Object[]{alias}
            );
        }

        java.security.Key privateKey;
        try {
            privateKey = crypto.getPrivateKey(alias, password);
            return privateKey.getEncoded();
        } catch (Exception e) {
            throw new WSSecurityException(WSSecurityException.FAILED_CHECK, null, null, e);
        }
    }
    
}
