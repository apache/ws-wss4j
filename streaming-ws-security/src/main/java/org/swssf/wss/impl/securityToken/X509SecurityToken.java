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
package org.swssf.wss.impl.securityToken;

import org.swssf.wss.ext.WSPasswordCallback;
import org.swssf.wss.ext.WSSConstants;
import org.swssf.wss.ext.WSSecurityContext;
import org.apache.xml.security.stax.crypto.Crypto;
import org.apache.xml.security.stax.crypto.CryptoType;
import org.apache.xml.security.stax.ext.SecurityToken;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityException;
import org.apache.xml.security.stax.ext.XMLSecurityUtils;

import javax.security.auth.callback.CallbackHandler;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public abstract class X509SecurityToken extends AbstractSecurityToken {
    private X509Certificate[] x509Certificates = null;
    private final XMLSecurityConstants.TokenType tokenType;

    protected X509SecurityToken(XMLSecurityConstants.TokenType tokenType, WSSecurityContext wsSecurityContext,
                                Crypto crypto, CallbackHandler callbackHandler, String id,
                                WSSConstants.KeyIdentifierType keyIdentifierType) {
        super(wsSecurityContext, crypto, callbackHandler, id, keyIdentifierType);
        this.tokenType = tokenType;
    }

    @Override
    public boolean isAsymmetric() {
        return true;
    }

    @Override
    protected Key getKey(String algorithmURI, XMLSecurityConstants.KeyUsage keyUsage) throws XMLSecurityException {
        WSPasswordCallback pwCb = new WSPasswordCallback(getAlias(), WSPasswordCallback.Usage.DECRYPT);
        XMLSecurityUtils.doPasswordCallback(getCallbackHandler(), pwCb);
        return getCrypto().getPrivateKey(getAlias(), pwCb.getPassword());
    }

    @Override
    protected PublicKey getPubKey(String algorithmURI, XMLSecurityConstants.KeyUsage keyUsage) throws XMLSecurityException {
        X509Certificate[] x509Certificates = getX509Certificates();
        if (x509Certificates == null || x509Certificates.length == 0) {
            return null;
        }
        return x509Certificates[0].getPublicKey();
    }

    @Override
    public X509Certificate[] getX509Certificates() throws XMLSecurityException {
        if (this.x509Certificates == null) {
            CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
            cryptoType.setAlias(getAlias());
            this.x509Certificates = getCrypto().getX509Certificates(cryptoType);
        }
        return this.x509Certificates;
    }

    @Override
    public void verify() throws XMLSecurityException {
        try {
            X509Certificate[] x509Certificates = getX509Certificates();
            if (x509Certificates != null && x509Certificates.length > 0) {
                x509Certificates[0].checkValidity();
                getCrypto().verifyTrust(x509Certificates);
            }
        } catch (CertificateExpiredException e) {
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_CHECK, e);
        } catch (CertificateNotYetValidException e) {
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_CHECK, e);
        }
    }

    @Override
    public SecurityToken getKeyWrappingToken() {
        return null;
    }

    protected abstract String getAlias() throws XMLSecurityException;

    @Override
    public XMLSecurityConstants.TokenType getTokenType() {
        return tokenType;
    }
}
