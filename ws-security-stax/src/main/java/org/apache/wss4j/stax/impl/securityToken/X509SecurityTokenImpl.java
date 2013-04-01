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
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.principal.PublicKeyPrincipalImpl;
import org.apache.wss4j.stax.ext.*;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.wss4j.stax.securityToken.X509SecurityToken;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import java.security.Key;
import java.security.Principal;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

public abstract class X509SecurityTokenImpl
        extends org.apache.xml.security.stax.impl.securityToken.X509SecurityToken implements X509SecurityToken {

    private CallbackHandler callbackHandler;
    private Crypto crypto;
    private WSSSecurityProperties securityProperties;
    private Principal principal;

    protected X509SecurityTokenImpl(WSSecurityTokenConstants.TokenType tokenType, WSInboundSecurityContext wsInboundSecurityContext,
                                    Crypto crypto, CallbackHandler callbackHandler, String id,
                                    WSSecurityTokenConstants.KeyIdentifier keyIdentifier,
                                    WSSSecurityProperties securityProperties) {
        super(tokenType, wsInboundSecurityContext, id, keyIdentifier);
        this.crypto = crypto;
        this.callbackHandler = callbackHandler;
        this.securityProperties = securityProperties;
    }

    protected Crypto getCrypto() {
        return crypto;
    }

    public CallbackHandler getCallbackHandler() {
        return callbackHandler;
    }

    @Override
    public Key getKey(String algorithmURI, XMLSecurityConstants.AlgorithmUsage algorithmUsage,
                      String correlationID) throws XMLSecurityException {
        WSPasswordCallback pwCb = new WSPasswordCallback(getAlias(), WSPasswordCallback.Usage.DECRYPT);
        WSSUtils.doPasswordCallback(getCallbackHandler(), pwCb);
        return getCrypto().getPrivateKey(getAlias(), pwCb.getPassword());
    }

    @Override
    public X509Certificate[] getX509Certificates() throws XMLSecurityException {
        if (super.getX509Certificates() == null) {
            String alias = getAlias();
            if (alias != null) {
                CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
                cryptoType.setAlias(alias);
                setX509Certificates(getCrypto().getX509Certificates(cryptoType));
            }
        }
        return super.getX509Certificates();
    }

    @Override
    public void verify() throws XMLSecurityException {
        //todo overall call verify on wrapping tokens for non top-level SecurityTokens!?
        try {
            X509Certificate[] x509Certificates = getX509Certificates();
            if (x509Certificates != null && x509Certificates.length > 0) {
                //todo I don't think the checkValidity is necessary because the CertPathChecker
                // in crypto-verify trust should already do the job
                x509Certificates[0].checkValidity();
                
                boolean enableRevocation = false;
                if (securityProperties != null) {
                    enableRevocation = securityProperties.isEnableRevocation();
                }
                getCrypto().verifyTrust(x509Certificates, enableRevocation);
            }
        } catch (CertificateExpiredException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, e);
        } catch (CertificateNotYetValidException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, e);
        }
    }

    protected abstract String getAlias() throws XMLSecurityException;

    @Override
    public Subject getSubject() throws WSSecurityException {
        return null;
    }

    @Override
    public Principal getPrincipal() throws WSSecurityException {
        if (this.principal == null) {
            try {
                X509Certificate[] certs = getX509Certificates();
                if (certs != null && certs.length > 0) {
                    return this.principal = certs[0].getSubjectX500Principal();
                }
                return this.principal = new PublicKeyPrincipalImpl(getPublicKey());
            } catch (XMLSecurityException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, e);
            }
        }
        return this.principal;
    }
}
