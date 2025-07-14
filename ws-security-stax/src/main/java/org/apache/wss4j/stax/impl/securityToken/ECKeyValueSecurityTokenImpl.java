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
import java.security.Principal;
import java.security.PublicKey;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.principal.PublicKeyPrincipalImpl;
import org.apache.wss4j.api.stax.ext.WSInboundSecurityContext;
import org.apache.wss4j.api.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.api.stax.securityToken.ECKeyValueSecurityToken;
import org.apache.xml.security.binding.xmldsig11.ECKeyValueType;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;

public class ECKeyValueSecurityTokenImpl
        extends org.apache.xml.security.stax.impl.securityToken.ECKeyValueSecurityToken
        implements ECKeyValueSecurityToken {

    private CallbackHandler callbackHandler;
    private Crypto crypto;
    private WSSSecurityProperties securityProperties;
    private Principal principal;

    public ECKeyValueSecurityTokenImpl(
            ECKeyValueType ecKeyValueType, WSInboundSecurityContext wsInboundSecurityContext, Crypto crypto,
            CallbackHandler callbackHandler, WSSSecurityProperties securityProperties)
            throws XMLSecurityException {
        super(ecKeyValueType, wsInboundSecurityContext);
        this.crypto = crypto;
        this.callbackHandler = callbackHandler;
        this.securityProperties = securityProperties;
    }

    @Override
    public void verify() throws XMLSecurityException {
        crypto.verifyTrust(getPublicKey());
    }

    @Override
    public Subject getSubject() throws WSSecurityException {
        return null;
    }

    @Override
    public Key getKey(String algorithmURI, XMLSecurityConstants.AlgorithmUsage algorithmUsage,
                      String correlationID) throws XMLSecurityException {
        PublicKey publicKey = getPublicKey();

        try {
            return crypto.getPrivateKey(publicKey, callbackHandler);
        } catch (WSSecurityException ex) {
            // Check to see if we are decrypting rather than signature verification
            Crypto decCrypto = securityProperties.getDecryptionCrypto();
            if (decCrypto != null && decCrypto != crypto) {
                return decCrypto.getPrivateKey(publicKey, callbackHandler);
            }
            throw ex;
        }
    }

    @Override
    public Principal getPrincipal() throws WSSecurityException {
        if (this.principal == null) {
            try {
                this.principal = new PublicKeyPrincipalImpl(getPublicKey());
            } catch (XMLSecurityException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, e);
            }
        }
        return this.principal;
    }
}
