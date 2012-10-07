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

import org.apache.ws.security.common.crypto.Crypto;
import org.apache.ws.security.common.ext.WSSecurityException;
import org.apache.ws.security.common.saml.SAMLKeyInfo;
import org.apache.ws.security.stax.ext.WSSConstants;
import org.apache.ws.security.stax.ext.WSSecurityContext;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.impl.securityToken.AbstractInboundSecurityToken;
import org.opensaml.common.SAMLVersion;

import javax.security.auth.callback.CallbackHandler;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SAMLSecurityToken extends AbstractInboundSecurityToken {

    private final SAMLVersion samlVersion;
    private final SAMLKeyInfo samlKeyInfo;
    private String issuer;
    private Crypto crypto;

    public SAMLSecurityToken(SAMLVersion samlVersion, SAMLKeyInfo samlKeyInfo, String issuer,
                             WSSecurityContext wsSecurityContext, Crypto crypto, CallbackHandler callbackHandler,
                             String id, WSSConstants.KeyIdentifierType keyIdentifierType) {
        super(wsSecurityContext, callbackHandler, id, keyIdentifierType);
        this.samlVersion = samlVersion;
        this.samlKeyInfo = samlKeyInfo;
        this.issuer = issuer;
        this.crypto = crypto;
        if (samlKeyInfo != null) {
            setSecretKey("", samlKeyInfo.getPrivateKey());
            setPublicKey(samlKeyInfo.getPublicKey());
            setX509Certificates(samlKeyInfo.getCerts());
        }
    }

    public SAMLSecurityToken(SAMLVersion samlVersion, SAMLKeyInfo samlKeyInfo, WSSecurityContext wsSecurityContext,
                             Crypto crypto, CallbackHandler callbackHandler, String id) {
        this(samlVersion, samlKeyInfo, null, wsSecurityContext, crypto, callbackHandler, id, null);
    }

    public Crypto getCrypto() {
        return crypto;
    }

    @Override
    public void verify() throws XMLSecurityException {
        try {
            X509Certificate[] x509Certificates = getX509Certificates();
            if (x509Certificates != null && x509Certificates.length > 0) {
                x509Certificates[0].checkValidity();
                //todo deprecated method:
                getCrypto().verifyTrust(x509Certificates);
            }
        } catch (CertificateExpiredException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION, e);
        } catch (CertificateNotYetValidException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION, e);
        }
    }

    @Override
    public XMLSecurityConstants.TokenType getTokenType() {
        if (samlVersion == SAMLVersion.VERSION_10) {
            return WSSConstants.Saml10Token;
        } else if (samlVersion == SAMLVersion.VERSION_11) {
            return WSSConstants.Saml11Token;
        }
        return WSSConstants.Saml20Token;
    }

    public SAMLKeyInfo getSamlKeyInfo() {
        //todo AlgoSecEvent?
        return samlKeyInfo;
    }

    public SAMLVersion getSamlVersion() {
        return samlVersion;
    }

    public String getIssuer() {
        return issuer;
    }
}
