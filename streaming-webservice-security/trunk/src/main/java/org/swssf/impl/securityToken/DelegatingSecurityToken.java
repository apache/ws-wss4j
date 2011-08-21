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

/**
 * This class wraps a SecurityToken and allows the token KeyIdentifierType to
 * be set differently by its actual usage
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class DelegatingSecurityToken implements SecurityToken {

    private Constants.KeyIdentifierType keyIdentifierType;
    private SecurityToken securityToken;

    public DelegatingSecurityToken(Constants.KeyIdentifierType keyIdentifierType, SecurityToken securityToken) {
        this.keyIdentifierType = keyIdentifierType;
        this.securityToken = securityToken;
    }

    public Constants.KeyIdentifierType getKeyIdentifierType() {
        return keyIdentifierType;
    }

    public SecurityToken getDelegatedSecurityToken() {
        return securityToken;
    }

    public String getId() {
        return securityToken.getId();
    }

    public Object getProcessor() {
        return securityToken.getProcessor();
    }

    public boolean isAsymmetric() {
        return securityToken.isAsymmetric();
    }

    public Key getSecretKey(String algorithmURI, Constants.KeyUsage keyUsage) throws WSSecurityException {
        return securityToken.getSecretKey(algorithmURI, keyUsage);
    }

    public PublicKey getPublicKey(Constants.KeyUsage keyUsage) throws WSSecurityException {
        return securityToken.getPublicKey(keyUsage);
    }

    public X509Certificate[] getX509Certificates() throws WSSecurityException {
        return securityToken.getX509Certificates();
    }

    public void verify() throws WSSecurityException {
        securityToken.verify();
    }

    public SecurityToken getKeyWrappingToken() {
        return securityToken.getKeyWrappingToken();
    }

    public String getKeyWrappingTokenAlgorithm() {
        return securityToken.getKeyWrappingTokenAlgorithm();
    }

    public Constants.TokenType getTokenType() {
        return securityToken.getTokenType();
    }
}
