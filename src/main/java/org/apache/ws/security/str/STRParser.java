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

import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.handler.RequestData;

import org.w3c.dom.Element;

import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Map;

/**
 * This interface describes a pluggable way of extracting credentials from SecurityTokenReference
 * elements. The implementations are used by various processors.
 */
public interface STRParser {
    
    /**
     * ISSUER_SERIAL - A certificate (chain) is located by the issuer name and serial number of the 
     * (root) cert
     * THUMBPRINT_SHA1 - A certificate (chain) is located by the SHA1 thumbprint of the (root) cert
     * KEY_IDENTIFIER - A certificate (chain) is located via a Key Identifier Element
     * DIRECT_REF - A certificate (chain) is located directly via an Id to another security token
     * Note that a Thumbprint reference is also a KeyIdentifier, but takes precedence over it.
     */
    enum REFERENCE_TYPE {
        ISSUER_SERIAL, THUMBPRINT_SHA1, KEY_IDENTIFIER, DIRECT_REF
    };
    
    /**
     * Parse a SecurityTokenReference element and extract credentials.
     * 
     * @param strElement The SecurityTokenReference element
     * @param data the RequestData associated with the request
     * @param wsDocInfo The WSDocInfo object to access previous processing results
     * @param parameters A set of implementation-specific parameters
     * @throws WSSecurityException
     */
    void parseSecurityTokenReference(
        Element strElement,
        RequestData data,
        WSDocInfo wsDocInfo,
        Map<String, Object> parameters
    ) throws WSSecurityException;
    
    /**
     * Get the X509Certificates associated with this SecurityTokenReference
     * @return the X509Certificates associated with this SecurityTokenReference
     */
    X509Certificate[] getCertificates();
    
    /**
     * Get the Principal associated with this SecurityTokenReference
     * @return the Principal associated with this SecurityTokenReference
     */
    Principal getPrincipal();
    
    /**
     * Get the PublicKey associated with this SecurityTokenReference
     * @return the PublicKey associated with this SecurityTokenReference
     */
    PublicKey getPublicKey();
    
    /**
     * Get the Secret Key associated with this SecurityTokenReference
     * @return the Secret Key associated with this SecurityTokenReference
     */
    byte[] getSecretKey();
    
    /**
     * Get whether the returned credential is already trusted or not. This is currently
     * applicable in the case of a credential extracted from a trusted HOK SAML Assertion,
     * and a BinarySecurityToken that has been processed by a Validator. In these cases,
     * the SignatureProcessor does not need to verify trust on the credential.
     * @return true if trust has already been verified on the returned Credential
     */
    boolean isTrustedCredential();

    /**
     * Get how the certificates were referenced
     * @return how the certificates were referenced
     */
    REFERENCE_TYPE getCertificatesReferenceType();
    
}
