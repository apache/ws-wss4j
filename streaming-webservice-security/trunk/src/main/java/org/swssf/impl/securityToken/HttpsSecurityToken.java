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

import org.swssf.ext.Constants;
import org.swssf.ext.SecurityToken;
import org.swssf.ext.WSSecurityException;

import java.security.Key;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.UUID;

/**
 * @author $Author: $
 * @version $Revision: $ $Date: $
 */
public class HttpsSecurityToken extends AbstractSecurityToken {

    private X509Certificate x509Certificate;
    private String username;
    private AuthenticationType authenticationType;

    private enum AuthenticationType {
        httpsClientAuthentication,
        httpBasicAuthentication,
        httpDigestAuthentication,
    }

    public HttpsSecurityToken(X509Certificate x509Certificate) throws WSSecurityException {
        super(null, null, UUID.randomUUID().toString(), null);
        this.x509Certificate = x509Certificate;
        this.authenticationType = AuthenticationType.httpsClientAuthentication;
    }

    public HttpsSecurityToken(boolean basicAuthentication, String username) throws WSSecurityException {
        super(null, null, UUID.randomUUID().toString(), null);
        if (basicAuthentication) {
            this.authenticationType = AuthenticationType.httpBasicAuthentication;
        } else {
            this.authenticationType = AuthenticationType.httpDigestAuthentication;
        }
        this.username = username;
    }

    public X509Certificate[] getX509Certificates() throws WSSecurityException {
        return new X509Certificate[]{this.x509Certificate};
    }

    public boolean isAsymmetric() {
        return true;
    }

    public Key getSecretKey(String algorithmURI, Constants.KeyUsage keyUsage) throws WSSecurityException {
        return null;
    }

    public PublicKey getPublicKey(Constants.KeyUsage keyUsage) throws WSSecurityException {
        if (x509Certificate != null) {
            return x509Certificate.getPublicKey();
        }
        return null;
    }

    public SecurityToken getKeyWrappingToken() {
        return null;
    }

    public String getKeyWrappingTokenAlgorithm() {
        return null;
    }

    public Constants.TokenType getTokenType() {
        return Constants.TokenType.HttpsToken;
    }
}
