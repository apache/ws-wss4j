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

import org.swssf.wss.ext.WSSConstants;
import org.swssf.xmlsec.ext.SecurityToken;
import org.swssf.xmlsec.ext.XMLSecurityConstants;
import org.swssf.xmlsec.ext.XMLSecurityException;

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

    private WSSConstants.KeyIdentifierType keyIdentifierType;
    private SecurityToken securityToken;

    public DelegatingSecurityToken(WSSConstants.KeyIdentifierType keyIdentifierType, SecurityToken securityToken) {
        this.keyIdentifierType = keyIdentifierType;
        this.securityToken = securityToken;
    }

    public WSSConstants.KeyIdentifierType getKeyIdentifierType() {
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

    public Key getSecretKey(String algorithmURI, XMLSecurityConstants.KeyUsage keyUsage) throws XMLSecurityException {
        return securityToken.getSecretKey(algorithmURI, keyUsage);
    }

    public PublicKey getPublicKey(XMLSecurityConstants.KeyUsage keyUsage) throws XMLSecurityException {
        return securityToken.getPublicKey(keyUsage);
    }

    public X509Certificate[] getX509Certificates() throws XMLSecurityException {
        return securityToken.getX509Certificates();
    }

    public void verify() throws XMLSecurityException {
        securityToken.verify();
    }

    public SecurityToken getKeyWrappingToken() {
        return securityToken.getKeyWrappingToken();
    }

    public String getKeyWrappingTokenAlgorithm() {
        return securityToken.getKeyWrappingTokenAlgorithm();
    }

    public XMLSecurityConstants.TokenType getTokenType() {
        return securityToken.getTokenType();
    }
}
