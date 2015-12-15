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

import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.apache.wss4j.dom.str.STRParser.REFERENCE_TYPE;

/**
 * This class holds the results from parsing a SecurityTokenReference Element by a STRParser implementation.
 */
public class STRParserResult {

    private X509Certificate[] certs;

    private byte[] secretKey;

    private PublicKey publicKey;

    private Principal principal;

    private boolean trustedCredential;

    private REFERENCE_TYPE referenceType;

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
        if (principal == null && certs != null && certs.length > 0) {
            principal = certs[0].getSubjectX500Principal();
        }

        return principal;
    }

    /**
     * Get the PublicKey associated with this SecurityTokenReference
     * @return the PublicKey associated with this SecurityTokenReference
     */
    public PublicKey getPublicKey() {
        return publicKey;
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
        return trustedCredential;
    }

    /**
     * Get how the certificates were referenced
     * @return how the certificates were referenced
     */
    public REFERENCE_TYPE getCertificatesReferenceType() {
        return referenceType;
    }

    public void setCerts(X509Certificate[] certs) {
        this.certs = certs;
    }

    public void setSecretKey(byte[] secretKey) {
        this.secretKey = secretKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public void setPrincipal(Principal principal) {
        this.principal = principal;
    }

    public void setTrustedCredential(boolean trustedCredential) {
        this.trustedCredential = trustedCredential;
    }

    public void setReferenceType(REFERENCE_TYPE referenceType) {
        this.referenceType = referenceType;
    }


}
