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

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.ext.WSInboundSecurityContext;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.xml.security.binding.xmldsig.X509IssuerSerialType;
import org.apache.xml.security.exceptions.XMLSecurityException;

import javax.security.auth.callback.CallbackHandler;
import java.security.cert.X509Certificate;

public class X509IssuerSerialTokenImpl extends X509SecurityTokenImpl {

    private String alias = null;
    private final X509IssuerSerialType x509IssuerSerialType;

    X509IssuerSerialTokenImpl(
            WSInboundSecurityContext wsInboundSecurityContext, Crypto crypto, CallbackHandler callbackHandler,
            X509IssuerSerialType x509IssuerSerialType, String id, WSSSecurityProperties securityProperties)
            throws XMLSecurityException {

        super(WSSecurityTokenConstants.X509V3Token, wsInboundSecurityContext, crypto, callbackHandler, id,
                WSSecurityTokenConstants.KeyIdentifier_IssuerSerial, securityProperties, false);

        if (x509IssuerSerialType.getX509IssuerName() == null
                || x509IssuerSerialType.getX509SerialNumber() == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, "noKeyinfo");
        }
        this.x509IssuerSerialType = x509IssuerSerialType;
    }

    @Override
    protected String getAlias() throws XMLSecurityException {
        if (this.alias == null) {
            CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ISSUER_SERIAL);
            cryptoType.setIssuerSerial(
                    x509IssuerSerialType.getX509IssuerName(), x509IssuerSerialType.getX509SerialNumber()
            );
            X509Certificate[] certs = getCrypto().getX509Certificates(cryptoType);
            setX509Certificates(certs);
            if (certs == null || certs.length == 0) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.SECURITY_TOKEN_UNAVAILABLE);
            }
            super.setX509Certificates(new X509Certificate[]{certs[0]});
            return this.alias = getCrypto().getX509Identifier(certs[0]);
        }
        return this.alias;
    }
}
