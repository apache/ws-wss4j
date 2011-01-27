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

package org.apache.ws.security.validate;

import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.apache.ws.security.message.token.Timestamp;
import org.apache.ws.security.message.token.UsernameToken;

/**
 * This class stores various Credential types that have to be validated by a Validator
 * implementation.
 */
public class Credential {
    
    private PublicKey publicKey;
    private X509Certificate[] certs;
    private Timestamp timestamp;
    private UsernameToken usernametoken;
    
    /**
     * Set a PublicKey to be validated
     * @param publicKey a PublicKey to be validated
     */
    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }
    
    /**
     * Get a PublicKey to be validated
     * @return a PublicKey to be validated
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }
    
    /**
     * Set an X509Certificate chain to be validated
     * @param certs an X509Certificate chain to be validated
     */
    public void setCertificates(X509Certificate[] certs) {
        this.certs = certs;
    }
    
    /**
     * Get an X509Certificate chain to be validated
     * @return an X509Certificate chain to be validated
     */
    public X509Certificate[] getCertificates() {
        return certs;
    }
    
    /**
     * Set a Timestamp to be validated
     * @param timestamp a Timestamp to be validated
     */
    public void setTimestamp(Timestamp timestamp) {
        this.timestamp = timestamp;
    }
    
    /**
     * Get a Timestamp to be validated
     * @return a Timestamp to be validated
     */
    public Timestamp getTimestamp() {
        return timestamp;
    }
    
    /**
     * Set a UsernameToken to be validated
     * @param usernametoken a UsernameToken to be validated
     */
    public void setUsernametoken(UsernameToken usernametoken) {
        this.usernametoken = usernametoken;
    }
    
    /**
     * Get a UsernameToken to be validated
     * @return a UsernameToken to be validated
     */
    public UsernameToken getUsernametoken() {
        return usernametoken;
    }
    
}
