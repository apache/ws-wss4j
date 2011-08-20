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

import org.opensaml.common.SAMLVersion;
import org.swssf.crypto.Crypto;
import org.swssf.ext.Constants;
import org.swssf.ext.SecurityContext;
import org.swssf.ext.SecurityToken;
import org.swssf.ext.WSSecurityException;
import org.swssf.impl.saml.SAMLKeyInfo;

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
public class SAMLSecurityToken extends AbstractAlgorithmSuiteSecurityEventFiringSecurityToken {

    private SAMLVersion samlVersion;
    private SAMLKeyInfo samlKeyInfo;
    private X509Certificate[] x509Certificate;

    public SAMLSecurityToken(SAMLVersion samlVersion, SAMLKeyInfo samlKeyInfo, SecurityContext securityContext, Crypto crypto, CallbackHandler callbackHandler, String id, Object processor) {
        super(securityContext, crypto, callbackHandler, id, processor);
        this.samlVersion = samlVersion;
        this.samlKeyInfo = samlKeyInfo;
    }

    public boolean isAsymmetric() {
        return true;
    }

    public Key getSecretKey(String algorithmURI, Constants.KeyUsage keyUsage) throws WSSecurityException {
        super.getSecretKey(algorithmURI, keyUsage);
        return samlKeyInfo.getPrivateKey();
    }

    public PublicKey getPublicKey(Constants.KeyUsage keyUsage) throws WSSecurityException {
        super.getPublicKey(keyUsage);
        PublicKey publicKey = samlKeyInfo.getPublicKey();
        if (publicKey == null) {
            publicKey = getX509Certificates()[0].getPublicKey();
        }
        return publicKey;
    }

    public X509Certificate[] getX509Certificates() throws WSSecurityException {
        if (this.x509Certificate == null) {
            this.x509Certificate = samlKeyInfo.getCerts();
        }
        return this.x509Certificate;
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

    public Constants.TokenType getTokenType() {
        if (samlVersion == SAMLVersion.VERSION_10) {
            return Constants.TokenType.Saml10Token;
        } else if (samlVersion == SAMLVersion.VERSION_11) {
            return Constants.TokenType.Saml11Token;
        }
        return Constants.TokenType.Saml20Token;
    }

    public SAMLKeyInfo getSamlKeyInfo() {
        //todo AlgoSecEvent?
        return samlKeyInfo;
    }
}
