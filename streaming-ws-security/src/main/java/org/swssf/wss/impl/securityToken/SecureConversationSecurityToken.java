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
import org.swssf.xmlsec.crypto.Crypto;
import org.swssf.xmlsec.ext.SecurityContext;
import org.swssf.xmlsec.ext.SecurityToken;
import org.swssf.xmlsec.ext.XMLSecurityConstants;
import org.swssf.xmlsec.ext.XMLSecurityException;

import javax.security.auth.callback.CallbackHandler;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SecureConversationSecurityToken extends AbstractAlgorithmSuiteSecurityEventFiringSecurityToken {

    //todo implement

    public SecureConversationSecurityToken(SecurityContext securityContext, Crypto crypto, CallbackHandler callbackHandler, String id, Object processor) {
        super(securityContext, crypto, callbackHandler, id, processor);
    }

    public boolean isAsymmetric() {
        return false;
    }

    public Key getSecretKey(String algorithmURI, XMLSecurityConstants.KeyUsage keyUsage) throws XMLSecurityException {
        super.getSecretKey(algorithmURI, keyUsage);
        return null;
    }

    public PublicKey getPublicKey(XMLSecurityConstants.KeyUsage keyUsage) throws XMLSecurityException {
        return null;
    }

    public X509Certificate[] getX509Certificates() throws XMLSecurityException {
        return null;
    }

    public void verify() throws XMLSecurityException {
    }

    public SecurityToken getKeyWrappingToken() {
        return null;
    }

    public String getKeyWrappingTokenAlgorithm() {
        return null;
    }

    public XMLSecurityConstants.TokenType getTokenType() {
        return WSSConstants.SecureConversationToken;
    }
}
