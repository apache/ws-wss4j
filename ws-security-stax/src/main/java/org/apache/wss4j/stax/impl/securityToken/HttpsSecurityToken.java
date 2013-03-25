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
import org.apache.xml.security.stax.impl.util.IDGenerator;

import java.security.Principal;
import java.security.cert.X509Certificate;

public class HttpsSecurityToken extends InboundSecurityTokenImpl {

    private String username;
    private final AuthenticationType authenticationType;

    private enum AuthenticationType {
        httpsClientAuthentication,
        httpBasicAuthentication,
        httpDigestAuthentication,
    }

    //todo the HttpsToken and the HttpsTokenSecEvent will be instantiated outside of wss4j so remove WSSecurityContext?
    public HttpsSecurityToken(X509Certificate x509Certificate, WSSecurityContext wsSecurityContext)
            throws XMLSecurityException {

        super(wsSecurityContext, IDGenerator.generateID(null), null);
        setX509Certificates(new X509Certificate[]{x509Certificate});
        this.authenticationType = AuthenticationType.httpsClientAuthentication;
    }

    //todo the HttpsToken and the HttpsTokenSecEvent will be instantiated outside of wss4j so remove WSSecurityContext?
    public HttpsSecurityToken(boolean basicAuthentication, String username, WSSecurityContext wsSecurityContext)
            throws XMLSecurityException {

        super(wsSecurityContext, IDGenerator.generateID(null), null);
        if (basicAuthentication) {
            this.authenticationType = AuthenticationType.httpBasicAuthentication;
        } else {
            this.authenticationType = AuthenticationType.httpDigestAuthentication;
        }
        this.username = username;
    }

    @Override
    public WSSConstants.TokenType getTokenType() {
        return WSSConstants.HttpsToken;
    }

    public String getUsername() {
        return username;
    }

    public AuthenticationType getAuthenticationType() {
        return authenticationType;
    }
    
    @Override
    public Principal getPrincipal() throws XMLSecurityException {
        X509Certificate[] certs = super.getX509Certificates();
        if (certs != null && certs.length > 0) {
            return certs[0].getSubjectX500Principal();
        }
        return null;
    }
}
