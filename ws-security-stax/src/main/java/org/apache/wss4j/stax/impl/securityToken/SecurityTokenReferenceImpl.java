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

import java.security.Key;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Deque;
import java.util.Map;

import org.apache.wss4j.stax.ext.WSInboundSecurityContext;
import org.apache.wss4j.stax.securityToken.SecurityTokenReference;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.impl.securityToken.AbstractInboundSecurityToken;
import org.apache.xml.security.stax.securityToken.InboundSecurityToken;

public class SecurityTokenReferenceImpl extends AbstractInboundSecurityToken implements SecurityTokenReference {

    private final InboundSecurityToken inboundSecurityToken;
    private final Deque<XMLSecEvent> xmlSecEvents;

    public SecurityTokenReferenceImpl(InboundSecurityToken inboundSecurityToken, Deque<XMLSecEvent> xmlSecEvents,
                                      WSInboundSecurityContext wsInboundSecurityContext, String id,
                                      WSSecurityTokenConstants.KeyIdentifier keyIdentifier) {
        super(wsInboundSecurityContext, id, keyIdentifier, true);
        this.inboundSecurityToken = inboundSecurityToken;
        this.xmlSecEvents = xmlSecEvents;
    }

    public Deque<XMLSecEvent> getXmlSecEvents() {
        return xmlSecEvents;
    }

    @Override
    public boolean isAsymmetric() throws XMLSecurityException {
        return inboundSecurityToken.isAsymmetric();
    }

    @Override
    public Map<String, Key> getSecretKey() throws XMLSecurityException {
        return inboundSecurityToken.getSecretKey();
    }

    @Override
    protected Key getKey(String algorithmURI, XMLSecurityConstants.AlgorithmUsage algorithmUsage,
                         String correlationID) throws XMLSecurityException {
        return inboundSecurityToken.getSecretKey(algorithmURI, algorithmUsage, correlationID);
    }

    @Override
    public PublicKey getPublicKey() throws XMLSecurityException {
        return inboundSecurityToken.getPublicKey();
    }

    @Override
    protected PublicKey getPubKey(String algorithmURI, XMLSecurityConstants.AlgorithmUsage algorithmUsage,
                                  String correlationID) throws XMLSecurityException {
        return inboundSecurityToken.getPublicKey(algorithmURI, algorithmUsage, correlationID);
    }

    @Override
    public X509Certificate[] getX509Certificates() throws XMLSecurityException {
        return inboundSecurityToken.getX509Certificates();
    }

    @Override
    public void verify() throws XMLSecurityException {
        inboundSecurityToken.verify();
    }

    @Override
    public InboundSecurityToken getKeyWrappingToken() throws XMLSecurityException {
        return (InboundSecurityToken)inboundSecurityToken.getKeyWrappingToken();
    }

    @Override
    public boolean isIncludedInMessage() {
        return inboundSecurityToken.isIncludedInMessage();
    }

    @Override
    public WSSecurityTokenConstants.TokenType getTokenType() {
        return inboundSecurityToken.getTokenType();
    }
}
