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
import org.apache.ws.security.message.token.DerivedKeyToken;
import org.apache.ws.security.message.token.Reference;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.saml.SAMLKeyInfo;
import org.apache.ws.security.saml.SAMLUtil;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Element;

import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;

public class SecurityTokenRefSTRParser implements STRParser {
    
    private byte[] secretKey;
    
    public void parseSecurityTokenReference(
        Element strElement,
        String algorithm,
        Crypto crypto,
        CallbackHandler cb,
        WSDocInfo wsDocInfo,
        WSSConfig wssConfig
    ) throws WSSecurityException {

        SecurityTokenReference secRef = new SecurityTokenReference(strElement);

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
                    secretKey = (byte[])result.get(WSSecurityEngineResult.TAG_DECRYPTED_KEY);
                } else if (WSConstants.DKT == action) {
                    DerivedKeyToken dkt = 
                        (DerivedKeyToken)result.get(WSSecurityEngineResult.TAG_DERIVED_KEY_TOKEN);
                    byte[] secret = 
                        (byte[])result.get(WSSecurityEngineResult.TAG_SECRET);
                    secretKey = dkt.deriveKey(WSSecurityUtil.getKeyLength(algorithm), secret);
                } else if (WSConstants.ST_UNSIGNED == action) {
                    Element samlElement = wsDocInfo.getTokenElement(id);
                    SAMLKeyInfo keyInfo = 
                        SAMLUtil.getSAMLKeyInfo(samlElement, crypto, cb);
                    // TODO Handle malformed SAML tokens where they don't have the 
                    // secret in them
                    secretKey = keyInfo.getSecret();
                } else if (WSConstants.SCT == action) {
                    secretKey = (byte[])result.get(WSSecurityEngineResult.TAG_SECRET);
                }
            } else {
                // Try custom token
                WSPasswordCallback pwcb = 
                    new WSPasswordCallback(id, WSPasswordCallback.CUSTOM_TOKEN);
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
                secretKey = pwcb.getKey();

                if (secretKey == null) {
                    throw new WSSecurityException(
                            WSSecurityException.FAILED_CHECK, "unsupportedKeyId"
                    );
                }
            }
        } else if (secRef.containsKeyIdentifier()){
            if (WSConstants.WSS_SAML_KI_VALUE_TYPE.equals(secRef.getKeyIdentifierValueType())) { 
                Element token = 
                    secRef.getKeyIdentifierTokenElement(strElement.getOwnerDocument(), wsDocInfo, cb);

                if (crypto == null) {
                    throw new WSSecurityException(
                            WSSecurityException.FAILURE, "noSigCryptoFile"
                    );
                }
                SAMLKeyInfo keyInfo = SAMLUtil.getSAMLKeyInfo(token, crypto, cb);
                // TODO Handle malformed SAML tokens where they don't have the 
                // secret in them
                secretKey = keyInfo.getSecret();
            } else {
                String keyIdentifierValue = secRef.getKeyIdentifierValue();
                WSPasswordCallback pwcb = 
                    new WSPasswordCallback(
                            keyIdentifierValue,
                            null,
                            secRef.getKeyIdentifierValueType(),
                            WSPasswordCallback.ENCRYPTED_KEY_TOKEN
                    );

                try {
                    Callback[] callbacks = new Callback[]{pwcb};
                    cb.handle(callbacks);
                } catch (Exception e) {
                    throw new WSSecurityException(
                            WSSecurityException.FAILURE,
                            "noPassword", 
                            new Object[] {keyIdentifierValue}, 
                            e
                    );
                }
                secretKey = pwcb.getKey();
            }
        } else {
            throw new WSSecurityException(WSSecurityException.FAILED_CHECK, "noReference");
        }
    }
    
    
    public void validateCredentials() throws WSSecurityException {
        //
    }
    
    public X509Certificate[] getCertificates() {
        return null;
    }
    
    public Principal getPrincipal() {
        return null;
    }
    
    public PublicKey getPublicKey() {
        return null;
    }
    
    public byte[] getSecretKey() {
        return secretKey;
    }
    
    
}
