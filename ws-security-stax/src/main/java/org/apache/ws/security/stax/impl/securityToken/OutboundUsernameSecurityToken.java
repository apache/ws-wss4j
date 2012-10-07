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
package org.apache.ws.security.stax.impl.securityToken;

import org.apache.ws.security.stax.ext.WSSConstants;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.config.JCEAlgorithmMapper;
import org.apache.xml.security.stax.impl.securityToken.GenericOutboundSecurityToken;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class OutboundUsernameSecurityToken extends GenericOutboundSecurityToken {

    private final UsernameToken usernameToken;

    public OutboundUsernameSecurityToken(String username, String password, String created, byte[] nonce, String id) {
        super(id, WSSConstants.UsernameToken);
        this.usernameToken = new UsernameToken(username, password, created, nonce, null, null);
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

    @Override
    public Key getSecretKey(String algorithmURI) throws XMLSecurityException {
        Key key = super.getSecretKey(algorithmURI);
        if (key != null) {
            return key;
        }

        byte[] secretToken = usernameToken.getSecretKey(getPassword(), WSSConstants.WSE_DERIVED_KEY_LEN, WSSConstants.LABEL_FOR_DERIVED_KEY);
        String algoFamily = JCEAlgorithmMapper.getJCERequiredKeyFromURI(algorithmURI);
        key = new SecretKeySpec(secretToken, algoFamily);
        setSecretKey(algorithmURI, key);
        return key;
    }
}
