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
 * This interface describes an abstract concept of a Credential to be validated.
 */
public class Credential {
    
    private PublicKey publicKey;
    private X509Certificate[] certs;
    private Timestamp timestamp;
    private UsernameToken usernametoken;
    
    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }
    
    public PublicKey getPublicKey() {
        return publicKey;
    }
    
    public void setCertificates(X509Certificate[] certs) {
        this.certs = certs;
    }
    
    public X509Certificate[] getCertificates() {
        return certs;
    }
    
    public void setTimestamp(Timestamp timestamp) {
        this.timestamp = timestamp;
    }
    
    public Timestamp getTimestamp() {
        return timestamp;
    }
    
    public void setUsernametoken(UsernameToken usernametoken) {
        this.usernametoken = usernametoken;
    }
    
    public UsernameToken getUsernametoken() {
        return usernametoken;
    }
    
}
