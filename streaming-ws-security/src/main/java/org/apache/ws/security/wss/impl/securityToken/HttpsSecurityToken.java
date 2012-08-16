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
package org.apache.ws.security.wss.impl.securityToken;

import org.apache.ws.security.wss.ext.WSSConstants;
import org.apache.ws.security.wss.ext.WSSecurityContext;
import org.apache.ws.security.wss.ext.WSSecurityException;
import org.apache.xml.security.stax.ext.SecurityToken;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.impl.securityToken.AbstractSecurityToken;
import org.apache.xml.security.stax.impl.util.IDGenerator;

import java.security.Key;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class HttpsSecurityToken extends AbstractSecurityToken {

    private X509Certificate x509Certificate;
    private String username;
    private final AuthenticationType authenticationType;

    private enum AuthenticationType {
        httpsClientAuthentication,
        httpBasicAuthentication,
        httpDigestAuthentication,
    }

    public HttpsSecurityToken(X509Certificate x509Certificate, WSSecurityContext wsSecurityContext) throws WSSecurityException {
        super(wsSecurityContext, null, IDGenerator.generateID(null), null);
        this.x509Certificate = x509Certificate;
        this.authenticationType = AuthenticationType.httpsClientAuthentication;
    }

    public HttpsSecurityToken(boolean basicAuthentication, String username, WSSecurityContext wsSecurityContext) throws WSSecurityException {
        super(wsSecurityContext, null, IDGenerator.generateID(null), null);
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

    protected Key getKey(String algorithmURI, XMLSecurityConstants.KeyUsage keyUsage) throws WSSecurityException {
        return null;
    }

    protected PublicKey getPubKey(String algorithmURI, XMLSecurityConstants.KeyUsage keyUsage) throws WSSecurityException {
        if (x509Certificate != null) {
            return x509Certificate.getPublicKey();
        }
        return null;
    }

    public SecurityToken getKeyWrappingToken() {
        return null;
    }

    public WSSConstants.TokenType getTokenType() {
        return WSSConstants.HttpsToken;
    }

    public X509Certificate getX509Certificate() {
        return x509Certificate;
    }

    public String getUsername() {
        return username;
    }

    public AuthenticationType getAuthenticationType() {
        return authenticationType;
    }
}
