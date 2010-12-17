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

package org.apache.ws.security.processor;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.message.token.DerivedKeyToken;
import org.apache.ws.security.message.token.Reference;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.message.token.UsernameToken;
import org.apache.ws.security.saml.SAMLKeyInfo;
import org.apache.ws.security.saml.SAMLUtil;
import org.w3c.dom.Element;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * The processor to process <code>wsc:DerivedKeyToken</code>.
 * 
 * @author Ruchith Fernando (ruchith.fernando@gmail.com)
 */
public class DerivedKeyTokenProcessor implements Processor {

    public List<WSSecurityEngineResult> handleToken(
        Element elem, 
        Crypto crypto, 
        Crypto decCrypto,
        CallbackHandler cb, 
        WSDocInfo wsDocInfo, 
        WSSConfig config
    ) throws WSSecurityException {
        
        // Deserialize the DKT
        DerivedKeyToken dkt = new DerivedKeyToken(elem);
        byte[] secret = extractSecret(wsDocInfo, dkt, cb, crypto);
        
        String tempNonce = dkt.getNonce();
        if (tempNonce == null) {
            throw new WSSecurityException("Missing wsc:Nonce value");
        }
        int length = dkt.getLength();
        if (length > 0) {
            byte[] keyBytes = dkt.deriveKey(length, secret);
            WSSecurityEngineResult result =
                new WSSecurityEngineResult(
                    WSConstants.DKT, null, keyBytes, null
                );
            wsDocInfo.addTokenElement(elem);
            result.put(WSSecurityEngineResult.TAG_ID, dkt.getID());
            result.put(WSSecurityEngineResult.TAG_DERIVED_KEY_TOKEN, dkt);
            result.put(WSSecurityEngineResult.TAG_SECRET, secret);
            wsDocInfo.addResult(result);
            return java.util.Collections.singletonList(result);
        }
        return new java.util.ArrayList<WSSecurityEngineResult>(0);
    }

    /**
     * @param wsDocInfo
     * @param dkt
     * @return the secret, as an array of bytes
     * @throws WSSecurityException
     */
    private byte[] extractSecret(
        WSDocInfo wsDocInfo, 
        DerivedKeyToken dkt, 
        CallbackHandler cb, 
        Crypto crypto
    ) throws WSSecurityException {
        SecurityTokenReference str = dkt.getSecurityTokenReference();
        if (str != null) {
            String uri = null;
            String keyIdentifierValueType = null;
            String keyIdentifierValue = null;
            
            WSSecurityEngineResult result = null;
            if (str.containsReference()) {
                Reference ref = str.getReference();
                uri = ref.getURI();
                if (uri.charAt(0) == '#') {
                    uri = uri.substring(1);
                }
                result = wsDocInfo.getResult(uri);
            } else {
                // Contains key identifier
                keyIdentifierValue = str.getKeyIdentifierValue();
                keyIdentifierValueType = str.getKeyIdentifierValueType();
                result = wsDocInfo.getResult(keyIdentifierValue);
            }
            
            if (result != null) {
                int action = ((Integer)result.get(WSSecurityEngineResult.TAG_ACTION)).intValue();
                if (WSConstants.UT == action) {
                    UsernameToken usernameToken = 
                        (UsernameToken)result.get(WSSecurityEngineResult.TAG_USERNAME_TOKEN);
                    return usernameToken.getDerivedKey();
                } else if (WSConstants.ENCR == action) {
                    return (byte[])result.get(WSSecurityEngineResult.TAG_DECRYPTED_KEY);
                } else if (WSConstants.SCT == action) {
                    return (byte[])result.get(WSSecurityEngineResult.TAG_SECRET);
                } else if (WSConstants.ST_UNSIGNED == action) {
                    Element samlElement = wsDocInfo.getTokenElement(uri);
                    SAMLKeyInfo keyInfo = 
                        SAMLUtil.getSAMLKeyInfo(samlElement, crypto, cb);
                    // TODO Handle malformed SAML tokens where they don't have the 
                    // secret in them
                    return keyInfo.getSecret();
                } else {
                    throw new WSSecurityException(
                        WSSecurityException.FAILED_CHECK, "unsupportedKeyId"
                    );
                }
            } else if (result == null && uri != null) {
                // Now use the callback and get it
                return getSecret(cb, uri);
            } else if (keyIdentifierValue != null && keyIdentifierValueType != null) {
                X509Certificate[] certs = str.getKeyIdentifier(crypto);
                if (certs == null || certs.length < 1 || certs[0] == null) {
                    return this.getSecret(cb, keyIdentifierValue, keyIdentifierValueType); 
                } else {
                    return this.getSecret(cb, crypto, certs);
                }
            } else {
                throw new WSSecurityException(
                    WSSecurityException.FAILED_CHECK, "unsupportedKeyId"
                );
            }
        } else {
            throw new WSSecurityException(WSSecurityException.FAILED_CHECK, "noReference");
        }
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
