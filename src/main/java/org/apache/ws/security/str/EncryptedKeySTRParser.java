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
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.message.token.BinarySecurity;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.message.token.X509Security;
import org.apache.ws.security.saml.SAMLKeyInfo;
import org.apache.ws.security.saml.SAMLUtil;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.w3c.dom.Element;

import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Map;

import javax.xml.namespace.QName;

/**
 * This implementation of STRParser is for parsing a SecurityTokenReference element, found in the
 * KeyInfo element associated with an EncryptedKey element
 */
public class EncryptedKeySTRParser implements STRParser {
    
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(EncryptedKeySTRParser.class);
    
    private X509Certificate[] certs;
    
    private REFERENCE_TYPE referenceType;
    
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
        Crypto crypto = data.getDecCrypto();
        WSSConfig config = data.getWssConfig();
        boolean bspCompliant = true;
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
            referenceType = REFERENCE_TYPE.DIRECT_REF;
        } else if (secRef.containsKeyIdentifier()) {
            uri = secRef.getKeyIdentifierValue();
            if (SecurityTokenReference.THUMB_URI.equals(secRef.getKeyIdentifierValueType())) {
                referenceType = REFERENCE_TYPE.THUMBPRINT_SHA1;
            } else {
                referenceType = REFERENCE_TYPE.KEY_IDENTIFIER;
            }
        }
        
        WSSecurityEngineResult result = wsDocInfo.getResult(uri);
        if (result != null) {
            processPreviousResult(result, secRef, data, wsDocInfo, bspCompliant);
        } else if (secRef.containsKeyIdentifier()) {
            if (WSConstants.WSS_SAML_KI_VALUE_TYPE.equals(secRef.getKeyIdentifierValueType())
                || WSConstants.WSS_SAML2_KI_VALUE_TYPE.equals(secRef.getKeyIdentifierValueType())) {
                AssertionWrapper assertion = 
                    SAMLUtil.getAssertionFromKeyIdentifier(
                        secRef, strElement, data, wsDocInfo
                    );
                if (bspCompliant) {
                    BSPEnforcer.checkSamlTokenBSPCompliance(secRef, assertion);
                }
                SAMLKeyInfo samlKi = 
                    SAMLUtil.getCredentialFromSubject(assertion, 
                                                      data, wsDocInfo, bspCompliant);
                certs = samlKi.getCerts();
            } else {
                if (bspCompliant) {
                    BSPEnforcer.checkBinarySecurityBSPCompliance(secRef, null);
                }
                certs = secRef.getKeyIdentifier(crypto);
            }
        } else if (secRef.containsX509Data() || secRef.containsX509IssuerSerial()) {
            referenceType = REFERENCE_TYPE.ISSUER_SERIAL;
            certs = secRef.getX509IssuerSerial(crypto);
        } else if (secRef.containsReference()) {
            Element bstElement = 
                secRef.getTokenElement(strElement.getOwnerDocument(), wsDocInfo, data.getCallbackHandler());

            // at this point ... check token type: Binary
            QName el = new QName(bstElement.getNamespaceURI(), bstElement.getLocalName());
            if (el.equals(WSSecurityEngine.BINARY_TOKEN)) {
                X509Security token = new X509Security(bstElement);
                if (bspCompliant) {
                    BSPEnforcer.checkBinarySecurityBSPCompliance(secRef, token);
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
        return referenceType;
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
        if (WSConstants.BST == action) {
            if (bspCompliant) {
                BinarySecurity token = 
                    (BinarySecurity)result.get(
                        WSSecurityEngineResult.TAG_BINARY_SECURITY_TOKEN
                    );
                BSPEnforcer.checkBinarySecurityBSPCompliance(secRef, token);
            }
            certs = 
                (X509Certificate[])result.get(
                    WSSecurityEngineResult.TAG_X509_CERTIFICATES
                );
        } else if (WSConstants.ST_UNSIGNED == action || WSConstants.ST_SIGNED == action) {
            AssertionWrapper assertion = 
                (AssertionWrapper)result.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
            if (bspCompliant) {
                BSPEnforcer.checkSamlTokenBSPCompliance(secRef, assertion);
            }
            SAMLKeyInfo keyInfo = 
                SAMLUtil.getCredentialFromSubject(assertion, 
                                                  data,
                                                  wsDocInfo, bspCompliant);
            certs = keyInfo.getCerts();
        } else {
            throw new WSSecurityException(
                WSSecurityException.UNSUPPORTED_SECURITY_TOKEN,
                "unsupportedBinaryTokenType",
                null
            );
        }
    }
    
}
