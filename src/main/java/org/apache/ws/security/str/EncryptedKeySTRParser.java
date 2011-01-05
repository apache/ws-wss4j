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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.message.token.X509Security;
import org.apache.ws.security.saml.SAMLKeyInfo;
import org.apache.ws.security.saml.SAMLUtil;
import org.w3c.dom.Element;

import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.xml.namespace.QName;

/**
 * This implementation of STRParser is for parsing a SecurityTokenReference element, found in the
 * KeyInfo element associated with an EncryptedKey element
 */
public class EncryptedKeySTRParser implements STRParser {
    
    private static final Log LOG = LogFactory.getLog(EncryptedKeySTRParser.class.getName());
    
    private X509Certificate[] certs;
    
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
        //
        // Handle X509IssuerSerial here. First check if all elements are available,
        // get the appropriate data, check if all data is available.
        // Then look up the certificate alias according to issuer name and serial number.
        //
        if (secRef.containsX509Data() || secRef.containsX509IssuerSerial()) {
            String alias = secRef.getX509IssuerSerialAlias(crypto);
            if (alias != null) {
                certs = crypto.getCertificates(alias);
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug("X509IssuerSerial alias: " + alias);
            }
        }
        //
        // If wsse:KeyIdentifier found, then the public key of the attached cert was used to
        // encrypt the session (symmetric) key that encrypts the data. Extract the certificate
        // using the BinarySecurity token (was enhanced to handle KeyIdentifier too).
        // This method is _not_ recommended by OASIS WS-S specification, X509 profile
        //
        else if (secRef.containsKeyIdentifier()) {
            if (WSConstants.WSS_SAML_KI_VALUE_TYPE.equals(secRef.getKeyIdentifierValueType())
                || WSConstants.WSS_SAML2_KI_VALUE_TYPE.equals(secRef.getKeyIdentifierValueType())) { 
                Element token = 
                    secRef.getKeyIdentifierTokenElement(strElement.getOwnerDocument(), wsDocInfo, cb);
                
                if (crypto == null) {
                    throw new WSSecurityException(
                        WSSecurityException.FAILURE, "noSigCryptoFile"
                    );
                }
                SAMLKeyInfo samlKi = SAMLUtil.getSAMLKeyInfo(token, crypto, cb);
                certs = samlKi.getCerts();
            } else {
                certs = secRef.getKeyIdentifier(crypto);
            }
        } else if (secRef.containsReference()) {
            if (wsDocInfo != null) {
                String uri = secRef.getReference().getURI();
                WSSecurityEngineResult result = wsDocInfo.getResult(uri);
                
                if (result != null) {
                    int action = ((Integer)result.get(WSSecurityEngineResult.TAG_ACTION)).intValue();
                    if (WSConstants.BST == action) {
                        certs = 
                            (X509Certificate[])result.get(
                                WSSecurityEngineResult.TAG_X509_CERTIFICATES
                            );
                    } else {
                        throw new WSSecurityException(
                            WSSecurityException.UNSUPPORTED_SECURITY_TOKEN,
                            "unsupportedBinaryTokenType",
                            null
                        );
                    }
                }
            }
            if (certs == null) {
                Element bstElement = 
                    secRef.getTokenElement(strElement.getOwnerDocument(), null, cb);
    
                // at this point ... check token type: Binary
                QName el = new QName(bstElement.getNamespaceURI(), bstElement.getLocalName());
                if (el.equals(WSSecurityEngine.BINARY_TOKEN)) {
                    X509Security token = new X509Security(bstElement);
                    if (token == null) {
                        throw new WSSecurityException(
                            WSSecurityException.UNSUPPORTED_SECURITY_TOKEN,
                            "unsupportedBinaryTokenType",
                            new Object[] {"for decryption (BST)"}
                        );
                    }
                    certs = new X509Certificate[]{token.getX509Certificate(crypto)};
                } else {
                    throw new WSSecurityException(
                        WSSecurityException.UNSUPPORTED_SECURITY_TOKEN,
                        "unsupportedBinaryTokenType",
                        null
                    );
                }
            }
        } else {
            throw new WSSecurityException(
                WSSecurityException.INVALID_SECURITY, "unsupportedKeyId"
            );
        }
        
        if (LOG.isDebugEnabled() && certs != null && certs[0] != null) {
            LOG.debug("cert: " + certs[0]);
        }
    }
    
    /**
     * Get the X509Certificates associated with this SecurityTokenReference
     * @return the X509Certificates associated with this SecurityTokenReference
     */
    public X509Certificate[] getCertificates() {
        return certs;
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
        return null;
    }
    
    
}
