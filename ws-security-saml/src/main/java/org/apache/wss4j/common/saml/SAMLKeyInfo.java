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

package org.apache.wss4j.common.saml;

import java.security.PublicKey;
import java.security.cert.X509Certificate;

/**
 * This holds key/cert information extracted from a SAML assertion
 */
public class SAMLKeyInfo {

    /**
     * Certificates
     */
    private X509Certificate[] certs;

    /**
     * Key bytes (e.g.: held in an encrypted key)
     */
    private byte[] secret;

    /**
     * The public key {e.g.: held in a ds:KeyInfo).
     */
    private PublicKey publicKey;

    public SAMLKeyInfo() {
    }

    public SAMLKeyInfo(X509Certificate[] certs) {
        this.certs = certs;
    }

    public SAMLKeyInfo(byte[] secret) {
        this.secret = secret;
    }

    public SAMLKeyInfo(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public X509Certificate[] getCerts() {
        return certs;
    }

    public void setCerts(X509Certificate[] certs) {
        this.certs = certs;
    }

    public byte[] getSecret() {
        return secret;
    }

    public void setSecret(byte[] secret) {
        this.secret = secret;
    }

    public PublicKey getPublicKey() {
        return this.publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

}
