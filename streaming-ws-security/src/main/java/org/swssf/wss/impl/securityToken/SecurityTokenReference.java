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
import org.swssf.wss.ext.WSSecurityContext;
import org.swssf.xmlsec.crypto.Crypto;
import org.swssf.xmlsec.ext.SecurityToken;
import org.swssf.xmlsec.ext.XMLSecurityConstants;
import org.swssf.xmlsec.ext.XMLSecurityException;

import javax.security.auth.callback.CallbackHandler;
import javax.xml.stream.events.XMLEvent;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Deque;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SecurityTokenReference extends AbstractSecurityToken {

    private SecurityToken securityToken;
    private Deque<XMLEvent> xmlEvents;

    public SecurityTokenReference(SecurityToken securityToken, Deque<XMLEvent> xmlEvents, WSSecurityContext wsSecurityContext,
                                  Crypto crypto, CallbackHandler callbackHandler, String id, WSSConstants.KeyIdentifierType keyIdentifierType, Object processor) {
        super(wsSecurityContext, crypto, callbackHandler, id, keyIdentifierType, processor);
        this.securityToken = securityToken;
        this.xmlEvents = xmlEvents;
    }

    public Deque<XMLEvent> getXmlEvents() {
        return xmlEvents;
    }

    public boolean isAsymmetric() {
        return securityToken.isAsymmetric();
    }

    protected Key getKey(String algorithmURI, XMLSecurityConstants.KeyUsage keyUsage) throws XMLSecurityException {
        return securityToken.getSecretKey(algorithmURI, keyUsage);
    }

    protected PublicKey getPubKey(String algorithmURI, XMLSecurityConstants.KeyUsage keyUsage) throws XMLSecurityException {
        return securityToken.getPublicKey(algorithmURI, keyUsage);
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
