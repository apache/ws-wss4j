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

import java.io.IOException;
import java.security.Key;

import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.ext.WSInboundSecurityContext;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.impl.securityToken.AbstractInboundSecurityToken;
import org.apache.xml.security.stax.securityToken.SecurityTokenConstants.TokenType;
import org.w3c.dom.Element;

public class ExternalSecurityTokenImpl extends AbstractInboundSecurityToken {

    private Element tokenElement;
    private byte[] key;

    public ExternalSecurityTokenImpl(WSInboundSecurityContext wsInboundSecurityContext, String id,
                                 WSSecurityTokenConstants.KeyIdentifier keyIdentifier,
                                 WSSSecurityProperties securityProperties,
                                 boolean included) throws WSSecurityException {
        super(wsInboundSecurityContext, id, keyIdentifier, included);
        if (securityProperties.getCallbackHandler() != null) {
            // Try to get the token from a CallbackHandler
            WSPasswordCallback pwcb =
                new WSPasswordCallback(id, WSPasswordCallback.CUSTOM_TOKEN);
            try {
                securityProperties.getCallbackHandler().handle(new Callback[]{pwcb});
            } catch (IOException | UnsupportedCallbackException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e, "noPassword");
            }

            this.tokenElement = pwcb.getCustomToken();
            this.key = pwcb.getKey();
        }

        if (this.tokenElement == null) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.SECURITY_TOKEN_UNAVAILABLE, "noToken",
                new Object[] {id}
            );
        }
    }

    @Override
    protected Key getKey(String algorithmURI, XMLSecurityConstants.AlgorithmUsage algorithmUsage, String correlationID) 
        throws XMLSecurityException {
        String keyAlgorithm = JCEMapper.getJCEKeyAlgorithmFromURI(algorithmURI);
        return new SecretKeySpec(key, keyAlgorithm);
    }

    @Override
    public TokenType getTokenType() {
        if ("SecurityContextToken".equals(tokenElement.getLocalName())) {
            return WSSecurityTokenConstants.SECURITY_CONTEXT_TOKEN;
        }
        return null;
    }

}
