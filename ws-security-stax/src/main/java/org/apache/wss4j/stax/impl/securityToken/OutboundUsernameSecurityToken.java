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
package org.apache.wss4j.stax.impl.securityToken;

import java.security.Key;

import javax.crypto.spec.SecretKeySpec;

import org.apache.wss4j.common.util.UsernameTokenUtil;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.config.JCEAlgorithmMapper;
import org.apache.xml.security.stax.impl.securityToken.GenericOutboundSecurityToken;

public class OutboundUsernameSecurityToken extends GenericOutboundSecurityToken {

    private String username;
    private String password;
    private String createdTime;
    private byte[] nonce;
    private byte[] salt;
    private int iterations;

    public OutboundUsernameSecurityToken(String username, String password, String createdTime, 
                                         byte[] nonce, String id, byte[] salt, int iterations) {
        super(id, WSSecurityTokenConstants.UsernameToken);
        this.username = username;
        this.password = password;
        this.createdTime = createdTime;
        this.nonce = nonce;
        this.salt = salt;
        this.iterations = iterations;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public String getCreated() {
        return createdTime;
    }

    public byte[] getNonce() {
        return nonce;
    }

    @Override
    public Key getSecretKey(String algorithmURI) throws XMLSecurityException {
        Key key = super.getSecretKey(algorithmURI);
        if (key != null) {
            return key;
        }
        
        byte[] secretToken = 
            UsernameTokenUtil.generateDerivedKey(getPassword(), salt, iterations);
        
        String algoFamily = JCEAlgorithmMapper.getJCEKeyAlgorithmFromURI(algorithmURI);
        key = new SecretKeySpec(secretToken, algoFamily);
        setSecretKey(algorithmURI, key);
        return key;

    }

}
