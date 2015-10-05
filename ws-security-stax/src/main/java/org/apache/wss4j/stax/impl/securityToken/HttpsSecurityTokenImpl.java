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

import java.security.Principal;
import java.security.cert.X509Certificate;

import javax.security.auth.Subject;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.securityToken.HttpsSecurityToken;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.impl.securityToken.AbstractInboundSecurityToken;
import org.apache.xml.security.stax.impl.util.IDGenerator;

public class HttpsSecurityTokenImpl extends AbstractInboundSecurityToken implements HttpsSecurityToken {

    private String username;
    private final AuthenticationType authenticationType;
    private Principal principal;

    private enum AuthenticationType {
        httpsClientAuthentication,
        httpBasicAuthentication,
        httpDigestAuthentication,
        noAuthentication
    }

    public HttpsSecurityTokenImpl() {
        super(null, IDGenerator.generateID(null), WSSecurityTokenConstants.KeyIdentifier_NoKeyInfo, true);
        this.authenticationType = AuthenticationType.noAuthentication;
    }
    
    public HttpsSecurityTokenImpl(X509Certificate x509Certificate) {
        super(null, IDGenerator.generateID(null), WSSecurityTokenConstants.KeyIdentifier_NoKeyInfo, true);
        setX509Certificates(new X509Certificate[]{x509Certificate});
        this.authenticationType = AuthenticationType.httpsClientAuthentication;
    }

    public HttpsSecurityTokenImpl(boolean basicAuthentication, String username) {
        super(null, IDGenerator.generateID(null), WSSecurityTokenConstants.KeyIdentifier_NoKeyInfo, true);
        if (basicAuthentication) {
            this.authenticationType = AuthenticationType.httpBasicAuthentication;
        } else {
            this.authenticationType = AuthenticationType.httpDigestAuthentication;
        }
        this.username = username;
    }

    @Override
    public WSSecurityTokenConstants.TokenType getTokenType() {
        return WSSecurityTokenConstants.HttpsToken;
    }

    //todo username from principal?
    public String getUsername() {
        return username;
    }

    public AuthenticationType getAuthenticationType() {
        return authenticationType;
    }

    @Override
    public Subject getSubject() throws WSSecurityException {
        return null;
    }

    @Override
    public Principal getPrincipal() throws WSSecurityException {
        if (this.principal == null) {
            try {
                X509Certificate[] certs = getX509Certificates();
                if (certs != null && certs.length > 0) {
                    return this.principal = certs[0].getSubjectX500Principal();
                }

            } catch (XMLSecurityException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, e);
            }
        }
        return this.principal;
    }
}
