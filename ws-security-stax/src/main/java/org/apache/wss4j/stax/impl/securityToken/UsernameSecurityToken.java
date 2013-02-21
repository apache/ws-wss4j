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

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSecurityContext;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.config.JCEAlgorithmMapper;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.impl.securityToken.AbstractInboundSecurityToken;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class UsernameSecurityToken extends AbstractInboundSecurityToken {

    private final UsernameToken usernameToken;
    private final WSSecurityContext wsSecurityContext;

    public UsernameSecurityToken(String username, String password, String created, byte[] nonce, byte[] salt, Long iteration,
                                 WSSecurityContext wsSecurityContext, String id, WSSConstants.KeyIdentifierType keyIdentifierType) {
        super(wsSecurityContext, id, keyIdentifierType);
        this.usernameToken = new UsernameToken(username, password, created, nonce, salt, iteration);
        this.wsSecurityContext = wsSecurityContext;
    }

    public String getUsername() {
        return usernameToken.getUsername();
    }

    public String getPassword() {
        return usernameToken.getPassword();
    }

    public String getCreated() {
        return usernameToken.getCreated();
    }

    public byte[] getNonce() {
        return usernameToken.getNonce();
    }

    public byte[] getSalt() {
        return usernameToken.getSalt();
    }

    public Long getIteration() {
        return usernameToken.getIteration();
    }

    /**
     * This method generates a derived key as defined in WSS Username
     * Token Profile.
     *
     * @return Returns the derived key a byte array
     * @throws WSSecurityException
     */
    public byte[] generateDerivedKey() throws WSSecurityException {
        return usernameToken.generateDerivedKey(wsSecurityContext);
    }

    @Override
    public boolean isAsymmetric() throws XMLSecurityException {
        return false;
    }

    @Override
    protected Key getKey(String algorithmURI, XMLSecurityConstants.KeyUsage keyUsage,
                         String correlationID) throws XMLSecurityException {

        Key key = getSecretKey().get(algorithmURI);
        if (key != null) {
            return key;
        }

        byte[] secretToken = usernameToken.generateDerivedKey(wsSecurityContext);
        String algoFamily = JCEAlgorithmMapper.getJCERequiredKeyFromURI(algorithmURI);
        key = new SecretKeySpec(secretToken, algoFamily);
        setSecretKey(algorithmURI, key);
        return key;
    }

    @Override
    public WSSConstants.TokenType getTokenType() {
        return WSSConstants.UsernameToken;
    }
}
