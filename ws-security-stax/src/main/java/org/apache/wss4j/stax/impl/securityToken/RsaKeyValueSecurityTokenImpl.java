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

import java.security.Principal;

import javax.security.auth.Subject;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.principal.PublicKeyPrincipalImpl;
import org.apache.wss4j.stax.ext.WSInboundSecurityContext;
import org.apache.wss4j.stax.securityToken.RsaKeyValueSecurityToken;
import org.apache.xml.security.binding.xmldsig.RSAKeyValueType;
import org.apache.xml.security.exceptions.XMLSecurityException;

public class RsaKeyValueSecurityTokenImpl
        extends org.apache.xml.security.stax.impl.securityToken.RsaKeyValueSecurityToken
        implements RsaKeyValueSecurityToken {

    private Crypto crypto;
    private Principal principal;

    public RsaKeyValueSecurityTokenImpl(
            RSAKeyValueType rsaKeyValueType, WSInboundSecurityContext wsInboundSecurityContext, Crypto crypto) {
        super(rsaKeyValueType, wsInboundSecurityContext);
        this.crypto = crypto;
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
