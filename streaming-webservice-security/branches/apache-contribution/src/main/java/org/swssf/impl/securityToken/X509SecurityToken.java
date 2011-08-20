/**
 * Copyright 2010, 2011 Marc Giger
 *
 * This file is part of the streaming-webservice-security-framework (swssf).
 *
 * The streaming-webservice-security-framework is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The streaming-webservice-security-framework is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with the streaming-webservice-security-framework.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.swssf.impl.securityToken;

import org.swssf.crypto.Crypto;
import org.swssf.ext.*;

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
public abstract class X509SecurityToken extends AbstractAlgorithmSuiteSecurityEventFiringSecurityToken {
    private X509Certificate[] x509Certificates = null;
    private Constants.TokenType tokenType;

    X509SecurityToken(Constants.TokenType tokenType, SecurityContext securityContext, Crypto crypto, CallbackHandler callbackHandler, String id, Object processor) {
        super(securityContext, crypto, callbackHandler, id, processor);
        this.tokenType = tokenType;
    }

    public boolean isAsymmetric() {
        return true;
    }

    public Key getSecretKey(String algorithmURI, Constants.KeyUsage keyUsage) throws WSSecurityException {
        super.getSecretKey(algorithmURI, keyUsage);
        WSPasswordCallback pwCb = new WSPasswordCallback(getAlias(), WSPasswordCallback.Usage.DECRYPT);
        Utils.doPasswordCallback(getCallbackHandler(), pwCb);
        return getCrypto().getPrivateKey(getAlias(), pwCb.getPassword());
    }

    public PublicKey getPublicKey(Constants.KeyUsage keyUsage) throws WSSecurityException {
        super.getPublicKey(keyUsage);
        X509Certificate[] x509Certificates = getX509Certificates();
        if (x509Certificates == null || x509Certificates.length == 0) {
            return null;
        }
        return x509Certificates[0].getPublicKey();
    }

    public X509Certificate[] getX509Certificates() throws WSSecurityException {
        if (this.x509Certificates == null) {
            this.x509Certificates = getCrypto().getCertificates(getAlias());
        }
        return this.x509Certificates;
    }

    public void verify() throws WSSecurityException {
        try {
            X509Certificate[] x509Certificates = getX509Certificates();
            if (x509Certificates != null && x509Certificates.length > 0) {
                x509Certificates[0].checkValidity();
                getCrypto().verifyTrust(x509Certificates);
            }
        } catch (CertificateExpiredException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, e);
        } catch (CertificateNotYetValidException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, e);
        }
    }

    public SecurityToken getKeyWrappingToken() {
        return null;
    }

    public String getKeyWrappingTokenAlgorithm() {
        return null;
    }

    protected abstract String getAlias() throws WSSecurityException;

    public Constants.TokenType getTokenType() {
        return tokenType;
    }
}
