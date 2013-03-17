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

import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSecurityContext;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.SecurityToken;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;

import java.security.Key;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Deque;
import java.util.Map;

public class SecurityTokenReference extends InboundSecurityTokenImpl {

    private final SecurityToken securityToken;
    private final Deque<XMLSecEvent> xmlSecEvents;

    public SecurityTokenReference(SecurityToken securityToken, Deque<XMLSecEvent> xmlSecEvents, WSSecurityContext wsSecurityContext,
                                  String id, WSSConstants.KeyIdentifierType keyIdentifierType) {
        super(wsSecurityContext, id, keyIdentifierType);
        this.securityToken = securityToken;
        this.xmlSecEvents = xmlSecEvents;
    }

    public Deque<XMLSecEvent> getXmlSecEvents() {
        return xmlSecEvents;
    }

    @Override
    public boolean isAsymmetric() throws XMLSecurityException {
        return securityToken.isAsymmetric();
    }

    @Override
    public Map<String, Key> getSecretKey() throws XMLSecurityException {
        return securityToken.getSecretKey();
    }

    @Override
    protected Key getKey(String algorithmURI, XMLSecurityConstants.KeyUsage keyUsage,
                         String correlationID) throws XMLSecurityException {
        return securityToken.getSecretKey(algorithmURI, keyUsage, correlationID);
    }

    @Override
    public PublicKey getPublicKey() throws XMLSecurityException {
        return securityToken.getPublicKey();
    }

    @Override
    protected PublicKey getPubKey(String algorithmURI, XMLSecurityConstants.KeyUsage keyUsage,
                                  String correlationID) throws XMLSecurityException {
        return securityToken.getPublicKey(algorithmURI, keyUsage, correlationID);
    }

    @Override
    public X509Certificate[] getX509Certificates() throws XMLSecurityException {
        return securityToken.getX509Certificates();
    }

    @Override
    public void verify() throws XMLSecurityException {
        securityToken.verify();
    }

    @Override
    public SecurityToken getKeyWrappingToken() throws XMLSecurityException {
        return securityToken.getKeyWrappingToken();
    }

    @Override
    public XMLSecurityConstants.TokenType getTokenType() {
        return securityToken.getTokenType();
    }
}
