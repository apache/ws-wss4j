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
package org.swssf.policy.assertionStates;

import org.apache.ws.secpolicy.WSSPolicyException;
import org.apache.ws.secpolicy.model.AbstractSecurityAssertion;
import org.apache.ws.secpolicy.model.AbstractToken;
import org.apache.ws.secpolicy.model.HttpsToken;
import org.swssf.wss.securityEvent.HttpsTokenSecurityEvent;
import org.swssf.wss.securityEvent.SecurityEvent;
import org.swssf.wss.securityEvent.TokenSecurityEvent;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */

public class HttpsTokenAssertionState extends TokenAssertionState {

    public HttpsTokenAssertionState(AbstractSecurityAssertion assertion, boolean asserted) {
        super(assertion, asserted);
    }

    @Override
    public SecurityEvent.Event[] getSecurityEventType() {
        return new SecurityEvent.Event[]{
                SecurityEvent.Event.HttpsToken
        };
    }

    @Override
    public boolean assertToken(TokenSecurityEvent tokenSecurityEvent, AbstractToken abstractToken) throws WSSPolicyException {
        if (!(tokenSecurityEvent instanceof HttpsTokenSecurityEvent)) {
            throw new WSSPolicyException("Expected a HttpsTokenSecurityEvent but got " + tokenSecurityEvent.getClass().getName());
        }
        HttpsTokenSecurityEvent httpsTokenSecurityEvent = (HttpsTokenSecurityEvent) tokenSecurityEvent;
        HttpsToken httpsToken = (HttpsToken) abstractToken;

        setAsserted(true);
        if (httpsToken.getIssuerName() != null && !httpsToken.getIssuerName().equals(httpsTokenSecurityEvent.getIssuerName())) {
            setAsserted(false);
            setErrorMessage("IssuerName in Policy (" + httpsToken.getIssuerName() + ") didn't match with the one in the HttpsToken (" + httpsTokenSecurityEvent.getIssuerName() + ")");
        }
        if (httpsToken.getAuthenticationType() != null) {
            switch (httpsToken.getAuthenticationType()) {
                case HttpBasicAuthentication:
                    if (httpsTokenSecurityEvent.getAuthenticationType() != HttpsTokenSecurityEvent.AuthenticationType.HttpBasicAuthentication) {
                        setAsserted(false);
                        setErrorMessage("Policy enforces HttpBasicAuthentication but we got " + httpsTokenSecurityEvent.getAuthenticationType());
                    }
                    break;
                case HttpDigestAuthentication:
                    if (httpsTokenSecurityEvent.getAuthenticationType() != HttpsTokenSecurityEvent.AuthenticationType.HttpDigestAuthentication) {
                        setAsserted(false);
                        setErrorMessage("Policy enforces HttpDigestAuthentication but we got " + httpsTokenSecurityEvent.getAuthenticationType());
                    }
                    break;
                case RequireClientCertificate:
                    if (httpsTokenSecurityEvent.getAuthenticationType() != HttpsTokenSecurityEvent.AuthenticationType.HttpsClientCertificateAuthentication) {
                        setAsserted(false);
                        setErrorMessage("Policy enforces HttClientCertificateAuthentication but we got " + httpsTokenSecurityEvent.getAuthenticationType());
                    }
                    break;
            }
        }
        return isAsserted();
    }
}
