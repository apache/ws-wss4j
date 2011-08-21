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
