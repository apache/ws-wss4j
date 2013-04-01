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

import org.apache.wss4j.common.derivedKey.AlgoFactory;
import org.apache.wss4j.common.derivedKey.ConversationConstants;
import org.apache.wss4j.common.derivedKey.ConversationException;
import org.apache.wss4j.common.derivedKey.DerivationAlgorithm;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.config.JCEAlgorithmMapper;
import org.apache.xml.security.stax.impl.securityToken.GenericOutboundSecurityToken;

import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.Key;

public class OutboundUsernameSecurityToken extends GenericOutboundSecurityToken {

    private String username;
    private String password;
    private String createdTime;
    private byte[] nonce;

    public OutboundUsernameSecurityToken(String username, String password, String createdTime, byte[] nonce, String id) {
        super(id, WSSecurityTokenConstants.UsernameToken);
        this.username = username;
        this.password = password;
        this.createdTime = createdTime;
        this.nonce = nonce;
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

        byte[] secretToken = getSecretKey(getPassword(), WSSConstants.WSE_DERIVED_KEY_LEN, WSSConstants.LABEL_FOR_DERIVED_KEY);
        String algoFamily = JCEAlgorithmMapper.getJCERequiredKeyFromURI(algorithmURI);
        key = new SecretKeySpec(secretToken, algoFamily);
        setSecretKey(algorithmURI, key);
        return key;
    }

    /**
     * Gets the secret key as per WS-Trust spec.
     *
     * @param keylen      How many bytes to generate for the key
     * @param labelString the label used to generate the seed
     * @return a secret key constructed from information contained in this
     *         username token
     */
    protected byte[] getSecretKey(String rawPassword, int keylen, String labelString) throws WSSecurityException {
        try {
            byte[] password = rawPassword.getBytes("UTF-8");
            byte[] label = labelString.getBytes("UTF-8");
            byte[] nonce = getNonce();
            byte[] created = getCreated().getBytes("UTF-8");
            byte[] seed = new byte[label.length + nonce.length + created.length];

            int offset = 0;
            System.arraycopy(label, 0, seed, offset, label.length);
            offset += label.length;

            System.arraycopy(nonce, 0, seed, offset, nonce.length);
            offset += nonce.length;

            System.arraycopy(created, 0, seed, offset, created.length);

            DerivationAlgorithm algo =
                    AlgoFactory.getInstance(ConversationConstants.DerivationAlgorithm.P_SHA_1);
            return algo.createKey(password, seed, 0, keylen);

        } catch (UnsupportedEncodingException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, e);
        } catch (ConversationException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, e);
        }
    }
}
